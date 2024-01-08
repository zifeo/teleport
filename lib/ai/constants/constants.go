package constants

import "github.com/sashabaranov/go-openai"

const (
	// DefaultGPTModel is the default GPT model used for various functions.
	DefaultGPTModel = openai.GPT4TurboPreview
	// DefaultLongContextGPTModel is the default GPT model used for various functions that require a long context.
	DefaultLongContextGPTModel = openai.GPT4TurboPreview
)
