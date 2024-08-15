package events

import (
	"github.com/gravitational/trace"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/protoadapt"
	"google.golang.org/protobuf/reflect/protopath"
	"google.golang.org/protobuf/reflect/protorange"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/runtime/protoiface"

	apievents "github.com/gravitational/teleport/api/types/events"
)

type protopathValue struct {
	Step  protopath.Step
	Value protoreflect.Value
}

func trimN(s string, n int) string {
	// Starting at 2 to leave room for quotes at the begging and end.
	charCount := 2
	for i, r := range s {
		// Make sure we always have room to add an escape character if necessary.
		if charCount+1 > n {
			return s[:i]
		}
		if r == rune('"') || r == '\\' {
			charCount++
		}
		charCount++
	}
	return s
}

func maxSizePerField(maxLength, customFields int) int {
	if customFields == 0 {
		return maxLength
	}
	return maxLength / customFields
}

func TrimToMaxSize(e apievents.AuditEvent, maxSize int) (apievents.AuditEvent, error) {
	if e.Size() <= maxSize {
		return e, nil
	}

	pm, ok := e.(protoiface.MessageV1)
	if !ok {
		return nil, trace.BadParameter("event %T is not a protobuf message", e)
	}
	protoEvent := protoadapt.MessageV2Of(pm)
	cloned := proto.Clone(protoEvent)

	stringFieldLengths := findStringLengths(cloned)
	totalStrLen := 0
	for _, strLen := range stringFieldLengths {
		totalStrLen += strLen
	}

	// this is safe as protoadapt.MessageV2Of will simply wrap the message
	// with a type that implements the protobuf v2 API, and
	// protoadapt.MessageV1Of will return the unwrapped message
	clonedAuditEvent := protoadapt.MessageV1Of(cloned).(apievents.AuditEvent)
	//Use 10% max size ballast + message size without custom fields.
	// clonedAuditEvent.Size is used instead of proto.Size(cloned) because
	// proto.Size uses reflection and is much slower.
	sizeBallast := maxSize/10 + (clonedAuditEvent.Size() - totalStrLen)
	maxSize -= sizeBallast

	maxFieldSize := maxSizePerField(maxSize, len(stringFieldLengths))

	if len(stringFieldLengths) != 0 {
		var leftover int
		for _, l := range stringFieldLengths {
			if l > maxFieldSize {
				continue
			}
			leftover += maxFieldSize - l
		}
		maxFieldSize += leftover / len(stringFieldLengths)
	}
	trimStrings(cloned, maxFieldSize)

	return clonedAuditEvent, nil
}

func findStringLengths(m protoreflect.ProtoMessage) []int {
	return processStrings(m, 0)
}

func trimStrings(m protoreflect.ProtoMessage, trimSize int) {
	processStrings(m, trimSize)
}

func processStrings(m protoreflect.ProtoMessage, trimSize int) []int {
	trim := trimSize != 0
	var strLens []int

	var rangeOptions protorange.Options
	rangeOptions.Range(m.ProtoReflect(), nil, func(v protopath.Values) error {
		last := v.Index(-1)
		if last.Step.Kind() == protopath.RootStep {
			return nil
		}

		// skip *Metadata messages
		if shouldSkipParentMessage(last) {
			return protorange.Break
		}

		curStr, ok := last.Value.Interface().(string)
		if !ok || len(curStr) == 0 {
			return nil
		}

		if !trim {
			strLens = append(strLens, len(curStr))

			if last.Step.Kind() == protopath.MapIndexStep {
				key := last.Step.MapIndex()
				keyStr, ok := key.Interface().(string)
				if !ok || len(keyStr) == 0 {
					return nil
				}
				strLens = append(strLens, len(keyStr))
			}
			return nil
		} else if len(curStr) <= trimSize {
			return nil
		}

		trimmedStr := trimN(curStr, trimSize)
		beforeLast := v.Index(-2)
		setStringValue(beforeLast, last, trimmedStr, func(s string) string {
			return trimN(s, trimSize)
		})
		return nil
	})

	return strLens
}

func shouldSkipParentMessage(last protopathValue) bool {
	parentName := getParentMessageName(last)
	return parentName == "Metadata"
}

func getParentMessageName(last protopathValue) string {
	fd := last.Step.FieldDescriptor()
	if fd == nil {
		return ""
	}

	parent := fd.Parent()
	if parent == nil {
		return ""
	}

	return string(parent.Name())
}

func setStringValue(beforeLast, last protopathValue, s string, modifyKey func(string) string) {
	strVal := protoreflect.ValueOfString(s)
	switch last.Step.Kind() {
	case protopath.FieldAccessStep:
		m := beforeLast.Value.Message()
		fd := last.Step.FieldDescriptor()
		m.Set(fd, strVal)
	case protopath.ListIndexStep:
		ls := beforeLast.Value.List()
		i := last.Step.ListIndex()
		ls.Set(i, strVal)
	case protopath.MapIndexStep:
		ms := beforeLast.Value.Map()
		key := last.Step.MapIndex()

		keyStr, ok := key.Interface().(string)
		if ok && len(keyStr) != 0 {
			ms.Clear(key)
			newKeyStr := modifyKey(keyStr)
			key = protoreflect.ValueOfString(newKeyStr).MapKey()
		}

		ms.Set(key, strVal)
	}
}
