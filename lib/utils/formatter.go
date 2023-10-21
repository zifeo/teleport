/*

 Copyright 2022 Gravitational, Inc.

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.


*/

package utils

import (
	"context"
	"encoding"
	"fmt"
	"io"
	"log/slog"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gravitational/trace"
	log "github.com/sirupsen/logrus"
	"golang.org/x/exp/slices"
)

type SLogTextHandler struct {
	mu *sync.Mutex
	w  io.Writer

	level     slog.Level
	formatter *TextFormatter

	goas      []groupOrAttrs
	component string
}

func NewSLogTextHandler(w io.Writer, level slog.Level, formatter *TextFormatter) *SLogTextHandler {
	return &SLogTextHandler{
		w:         w,
		level:     level,
		formatter: formatter,
		mu:        &sync.Mutex{},
	}
}

// groupOrAttrs holds either a group name or a list of slog.Attrs.
type groupOrAttrs struct {
	group string      // group name if non-empty
	attrs []slog.Attr // attrs if non-empty
}

func (s *SLogTextHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return level >= s.level.Level()
}

func (s *SLogTextHandler) Handle(ctx context.Context, record slog.Record) error {
	return s.formatter.FormatRecord(s, record)
}

func (s *SLogTextHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	if len(attrs) == 0 {
		return s
	}
	return s.withGroupOrAttrs(groupOrAttrs{attrs: attrs})
}

func (s *SLogTextHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return s
	}
	return s.withGroupOrAttrs(groupOrAttrs{group: name})
}

func (s *SLogTextHandler) withGroupOrAttrs(goa groupOrAttrs) *SLogTextHandler {
	h2 := *s
	h2.goas = make([]groupOrAttrs, len(s.goas)+1)
	copy(h2.goas, s.goas)

	idx := slices.IndexFunc(goa.attrs, func(attr slog.Attr) bool {
		return attr.Key == trace.Component
	})

	var component string
	if idx >= 0 {
		component = goa.attrs[idx].Value.String()
		goa.attrs = goa.attrs[:idx+copy(goa.attrs[idx:], goa.attrs[idx+1:])]
	}

	h2.goas[len(h2.goas)-1] = goa
	h2.component = component

	return &h2
}

type TextFormatter struct {
	// ComponentPadding is a padding to pick when displaying
	// and formatting component field, defaults to DefaultComponentPadding
	ComponentPadding int
	// EnableColors enables colored output
	EnableColors bool
	// FormatCaller is a function to return (part) of source file path for output.
	// Defaults to filePathAndLine() if unspecified
	FormatCaller func() (caller string)
	// ExtraFields represent the extra fields that will be added to the log message
	ExtraFields []string
	// TimestampEnabled specifies if timestamp is enabled in logs
	timestampEnabled bool
	// CallerEnabled specifies if caller is enabled in logs
	callerEnabled bool
}

type writer struct {
	buffer *Buffer
}

const (
	noColor        = -1
	red            = 31
	yellow         = 33
	blue           = 36
	gray           = 37
	levelField     = "level"
	componentField = "component"
	callerField    = "caller"
	timestampField = "timestamp"
	messageField   = "message"
)

func NewDefaultTextFormatter(enableColors bool) *TextFormatter {
	return &TextFormatter{
		ComponentPadding: trace.DefaultComponentPadding,
		FormatCaller:     formatCallerWithPathAndLine,
		ExtraFields:      KnownFormatFields.names(),
		EnableColors:     enableColors,
		callerEnabled:    true,
		timestampEnabled: false,
	}
}

// CheckAndSetDefaults checks and sets log format configuration
func (tf *TextFormatter) CheckAndSetDefaults() error {
	// set padding
	if tf.ComponentPadding == 0 {
		tf.ComponentPadding = trace.DefaultComponentPadding
	}
	// set caller
	tf.FormatCaller = formatCallerWithPathAndLine

	// set log formatting
	if tf.ExtraFields == nil {
		tf.timestampEnabled = true
		tf.callerEnabled = true
		tf.ExtraFields = KnownFormatFields.names()
		return nil
	}
	// parse input
	res, err := parseInputFormat(tf.ExtraFields)
	if err != nil {
		return trace.Wrap(err)
	}

	if slices.Contains(res, timestampField) {
		tf.timestampEnabled = true
	}

	if slices.Contains(res, callerField) {
		tf.callerEnabled = true
	}

	tf.ExtraFields = res
	return nil
}

func (tf *TextFormatter) FormatRecord(h *SLogTextHandler, r slog.Record) error {
	writer := writer{buffer: New()}
	defer writer.buffer.Free()

	// write timestamp first if enabled
	if tf.timestampEnabled && !r.Time.IsZero() {
		writer.writeField(r.Time.Format(time.RFC3339), noColor)
	}

	for _, match := range tf.ExtraFields {
		switch match {
		case "level":
			color := noColor
			if tf.EnableColors {
				switch r.Level {
				case slog.LevelDebug, slog.LevelDebug + slog.LevelDebug:
					color = gray
				case slog.LevelWarn:
					color = yellow
				case slog.LevelError:
					color = red
				default:
					color = blue
				}
			}
			writer.writeField(strings.ToUpper(padMax(r.Level.String(), trace.DefaultLevelPadding)), color)
		case "component":
			padding := trace.DefaultComponentPadding
			if tf.ComponentPadding != 0 {
				padding = tf.ComponentPadding
			}
			if len(*writer.buffer) > 0 {
				writer.buffer.WriteByte(' ')
			}

			component := h.component
			if component != "" {
				component = fmt.Sprintf("[%v]", component)
			}
			component = strings.ToUpper(padMax(component, padding))
			if component[len(component)-1] != ' ' {
				component = component[:len(component)-1] + "]"
			}
			writer.buffer.WriteString(component)
		default:
			if !KnownFormatFields.has(match) {
				return trace.BadParameter("invalid log format key: %v", match)
			}
		}
	}

	// always use message
	if r.Message != "" {
		writer.writeField(r.Message, noColor)
	}

	goas := h.goas
	if r.NumAttrs() == 0 {
		// If the record has no Attrs, remove groups at the end of the list; they are empty.
		for len(goas) > 0 && goas[len(goas)-1].group != "" {
			goas = goas[:len(goas)-1]
		}
	}
	for _, goa := range goas {
		if goa.group != "" {
			writer.buffer.WriteString(goa.group)
			continue
		}

		for _, a := range goa.attrs {
			writer.writeKeyValue(a.Key, a.Value)
		}
	}

	r.Attrs(func(attr slog.Attr) bool {
		if attr.Key == trace.Component {
			return true
		}
		switch value := attr.Value.Any().(type) {
		case map[string]any:
			writer.writeMap(value)
		default:
			writer.writeKeyValue(attr.Key, value)
		}
		return true
	})

	// write caller last if enabled
	if tf.callerEnabled && r.PC != 0 {
		fs := runtime.CallersFrames([]uintptr{r.PC})
		f, _ := fs.Next()

		count := 0
		idx := strings.LastIndexFunc(f.File, func(r rune) bool {
			if r == '/' {
				count++
			}

			return count == 2
		})

		fmt.Fprintf(writer.buffer, "%s:%d", f.File[idx+1:], f.Line)
	}

	writer.buffer.WriteByte('\n')

	h.mu.Lock()
	defer h.mu.Unlock()
	_, err := h.w.Write(*writer.buffer)
	return trace.Wrap(err)
}

// Format formats each log line as configured in teleport config file
func (tf *TextFormatter) Format(e *log.Entry) ([]byte, error) {
	w := &writer{buffer: New()}

	// write timestamp first if enabled
	if tf.timestampEnabled && !e.Time.IsZero() {
		w.writeField(e.Time.Format(time.RFC3339), noColor)
	}

	for _, match := range tf.ExtraFields {
		switch match {
		case "level":
			color := noColor
			if tf.EnableColors {
				switch e.Level {
				case log.DebugLevel, log.TraceLevel:
					color = gray
				case log.WarnLevel:
					color = yellow
				case log.ErrorLevel, log.FatalLevel, log.PanicLevel:
					color = red
				default:
					color = blue
				}
			}
			w.writeField(strings.ToUpper(padMax(e.Level.String(), trace.DefaultLevelPadding)), color)
		case "component":
			padding := trace.DefaultComponentPadding
			if tf.ComponentPadding != 0 {
				padding = tf.ComponentPadding
			}
			if len(*w.buffer) > 0 {
				w.buffer.WriteByte(' ')
			}
			value := e.Data[trace.Component]
			var component string
			if reflect.ValueOf(value).IsValid() {
				component = fmt.Sprintf("[%v]", value)
			}
			component = strings.ToUpper(padMax(component, padding))
			if component[len(component)-1] != ' ' {
				component = component[:len(component)-1] + "]"
			}
			w.buffer.WriteString(component)
		default:
			if !KnownFormatFields.has(match) {
				return nil, trace.BadParameter("invalid log format key: %v", match)
			}
		}
	}

	// always use message
	if e.Message != "" {
		w.writeField(e.Message, noColor)
	}

	caller := e.Data[callerField]
	delete(e.Data, callerField)
	if len(e.Data) > 0 {
		w.writeMap(e.Data)
	}

	// write caller last if enabled
	if tf.callerEnabled {
		if caller == nil {
			caller = tf.FormatCaller()
		}

		if caller != "" {
			w.writeField(caller, noColor)
		}
	}

	w.buffer.WriteByte('\n')
	return *w.buffer, nil
}

// JSONFormatter implements the logrus.Formatter interface and adds extra
// fields to log entries
type JSONFormatter struct {
	log.JSONFormatter

	ExtraFields []string

	callerEnabled    bool
	componentEnabled bool
}

// CheckAndSetDefaults checks and sets log format configuration
func (j *JSONFormatter) CheckAndSetDefaults() error {
	// set log formatting
	if j.ExtraFields == nil {
		j.ExtraFields = KnownFormatFields.names()
	}

	// parse input
	res, err := parseInputFormat(j.ExtraFields)
	if err != nil {
		return trace.Wrap(err)
	}

	if slices.Contains(res, timestampField) {
		j.JSONFormatter.DisableTimestamp = true
	}

	if slices.Contains(res, callerField) {
		j.callerEnabled = true
	}

	if slices.Contains(res, componentField) {
		j.componentEnabled = true
	}

	// rename default fields
	j.JSONFormatter = log.JSONFormatter{
		FieldMap: log.FieldMap{
			log.FieldKeyTime:  timestampField,
			log.FieldKeyLevel: levelField,
			log.FieldKeyMsg:   messageField,
		},
	}

	return nil
}

// Format implements logrus.Formatter interface
func (j *JSONFormatter) Format(e *log.Entry) ([]byte, error) {
	if j.callerEnabled && e.Data[callerField] == nil {
		path := formatCallerWithPathAndLine()
		e.Data[callerField] = path
	}

	if j.componentEnabled {
		e.Data[componentField] = e.Data[trace.Component]
	}

	delete(e.Data, trace.Component)

	if j.callerEnabled {
		if v, ok := e.Data[callerField]; ok {
			switch caller := v.(type) {
			case string:
			case source:
				e.Data[callerField] = caller.String()
			}
		}
	}

	return j.JSONFormatter.Format(e)
}

func NewTestJSONFormatter() *JSONFormatter {
	formatter := &JSONFormatter{}
	if err := formatter.CheckAndSetDefaults(); err != nil {
		panic(err)
	}
	return formatter
}

func (w *writer) writeError(value any) {
	switch err := value.(type) {
	case trace.Error:
		fmt.Fprintf(w.buffer, "[%v]", err.DebugReport())
	default:
		fmt.Fprintf(w.buffer, "[%v]", value)
	}
}

func padMax(in string, chars int) string {
	switch {
	case len(in) < chars:
		return in + strings.Repeat(" ", chars-len(in))
	default:
		return in[:chars]
	}
}

func (w *writer) writeField(value any, color int) {
	if len(*w.buffer) > 0 {
		w.buffer.WriteByte(' ')
	}

	w.writeValue(value, color)
}

func (w *writer) writeKeyValue(key string, value any) {
	if len(*w.buffer) > 0 {
		w.buffer.WriteByte(' ')
	}
	w.buffer.WriteString(key)
	w.buffer.WriteByte(':')
	if key == log.ErrorKey {
		w.writeError(value)
		return
	}
	w.writeValue(value, noColor)
}

func (w *writer) writeValue(value interface{}, color int) {
	switch v := value.(type) {
	case string:
		if needsQuoting(v) {
			if color == noColor {
				*w.buffer = strconv.AppendQuote(*w.buffer, v)
				return
			}

			w.buffer.WriteString("\x1b[")
			w.buffer.WritePosInt(color)
			w.buffer.WriteString("m")
			*w.buffer = strconv.AppendQuote(*w.buffer, v)
			w.buffer.WriteString("\x1b[0m")
			return
		}

		if color == noColor {
			w.buffer.WriteString(v)
			return
		}

		w.buffer.WriteString("\x1b[")
		w.buffer.WritePosInt(color)
		w.buffer.WriteString("m")
		w.buffer.WriteString(v)
		w.buffer.WriteString("\x1b[0m")
		return
	default:
		if color == noColor {
			fmt.Fprintf(w.buffer, "%v", v)
			return
		}

		w.buffer.WriteString("\x1b[")
		w.buffer.WritePosInt(color)
		w.buffer.WriteString("m")

		if tm, ok := v.(encoding.TextMarshaler); ok {
			data, err := tm.MarshalText()
			if err != nil {
				return
			}
			// TODO: avoid the conversion to string.
			w.writeValue(data, color)
			return
		}
		fmt.Fprintf(w.buffer, "\x1b[%dm%v\x1b[0m", color, v)
	}
}

func (w *writer) writeMap(m map[string]any) {
	if len(m) == 0 {
		return
	}
	keys := make([]string, 0, len(m))
	for key := range m {
		if key == trace.Component {
			continue
		}
		keys = append(keys, key)
	}

	slices.Sort(keys)
	for _, key := range keys {
		switch value := m[key].(type) {
		case map[string]any:
			w.writeMap(value)
		case log.Fields:
			w.writeMap(value)
		default:
			w.writeKeyValue(key, value)
		}
	}
}

type frameCursor struct {
	// current specifies the current stack frame.
	// if omitted, rest contains the complete stack
	current *runtime.Frame
	// rest specifies the rest of stack frames to explore
	rest *runtime.Frames
	// n specifies the total number of stack frames
	n int
}

// formatCallerWithPathAndLine formats the caller in the form path/segment:<line number>
// for output in the log
func formatCallerWithPathAndLine() (path string) {
	if cursor := findFrame(); cursor != nil {
		t := newTraceFromFrames(*cursor, nil)
		return t.Loc()
	}
	return ""
}

var frameIgnorePattern = regexp.MustCompile(`github\.com/sirupsen/logrus`)

// findFrames positions the stack pointer to the first
// function that does not match the frameIngorePattern
// and returns the rest of the stack frames
func findFrame() *frameCursor {
	var buf [32]uintptr
	// Skip enough frames to start at user code.
	// This number is a mere hint to the following loop
	// to start as close to user code as possible and getting it right is not mandatory.
	// The skip count might need to get updated if the call to findFrame is
	// moved up/down the call stack
	n := runtime.Callers(4, buf[:])
	pcs := buf[:n]
	frames := runtime.CallersFrames(pcs)
	for i := 0; i < n; i++ {
		frame, _ := frames.Next()
		if !frameIgnorePattern.MatchString(frame.Function) {
			return &frameCursor{
				current: &frame,
				rest:    frames,
				n:       n,
			}
		}
	}
	return nil
}

func newTraceFromFrames(cursor frameCursor, err error) *trace.TraceErr {
	traces := make(trace.Traces, 0, cursor.n)
	if cursor.current != nil {
		traces = append(traces, frameToTrace(*cursor.current))
	}
	for {
		frame, more := cursor.rest.Next()
		traces = append(traces, frameToTrace(frame))
		if !more {
			break
		}
	}
	return &trace.TraceErr{
		Err:    err,
		Traces: traces,
	}
}

func frameToTrace(frame runtime.Frame) trace.Trace {
	return trace.Trace{
		Func: frame.Function,
		Path: frame.File,
		Line: frame.Line,
	}
}

func (r knownFormatFieldsMap) has(name string) bool {
	_, ok := r[name]
	return ok
}

func (r knownFormatFieldsMap) names() (result []string) {
	for k := range r {
		result = append(result, k)
	}
	return result
}

type knownFormatFieldsMap map[string]struct{}

// KnownFormatFields are the known fields for log entries
var KnownFormatFields = knownFormatFieldsMap{
	levelField:     {},
	componentField: {},
	callerField:    {},
	timestampField: {},
}

func parseInputFormat(formatInput []string) (result []string, err error) {
	for _, component := range formatInput {
		component = strings.TrimSpace(component)
		if !KnownFormatFields.has(component) {
			return nil, trace.BadParameter("invalid log format key: %q", component)
		}
		result = append(result, component)
	}
	return result, nil
}

// buffer adapted from go/src/fmt/print.go
type Buffer []byte

// Having an initial size gives a dramatic speedup.
var bufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 0, 1024)
		return (*Buffer)(&b)
	},
}

func New() *Buffer {
	return bufPool.Get().(*Buffer)
}

func (b *Buffer) Free() {
	// To reduce peak allocation, return only smaller buffers to the pool.
	const maxBufferSize = 16 << 10
	if cap(*b) <= maxBufferSize {
		*b = (*b)[:0]
		bufPool.Put(b)
	}
}

func (b *Buffer) Reset() {
	*b = (*b)[:0]
}

func (b *Buffer) Write(p []byte) (int, error) {
	*b = append(*b, p...)
	return len(p), nil
}

func (b *Buffer) WriteString(s string) (int, error) {
	*b = append(*b, s...)
	return len(s), nil
}

func (b *Buffer) WriteByte(c byte) error {
	*b = append(*b, c)
	return nil
}

func (b *Buffer) WritePosInt(i int) {
	b.WritePosIntWidth(i, 0)
}

// WritePosIntWidth writes non-negative integer i to the buffer, padded on the left
// by zeroes to the given width. Use a width of 0 to omit padding.
func (b *Buffer) WritePosIntWidth(i, width int) {
	// Cheap integer to fixed-width decimal ASCII.
	// Copied from log/log.go.

	if i < 0 {
		panic("negative int")
	}

	// Assemble decimal in reverse order.
	var bb [20]byte
	bp := len(bb) - 1
	for i >= 10 || width > 1 {
		width--
		q := i / 10
		bb[bp] = byte('0' + i - q*10)
		bp--
		i = q
	}
	// i < 10
	bb[bp] = byte('0' + i)
	b.Write(bb[bp:])
}

func (b *Buffer) String() string {
	return string(*b)
}
