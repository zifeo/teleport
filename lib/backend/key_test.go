// Teleport
// Copyright (C) 2024 Gravitational, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package backend_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/gravitational/teleport/lib/backend"
)

func TestKeyString(t *testing.T) {
	tests := []struct {
		name     string
		expected string
		key      backend.Key
	}{
		{
			name: "empty key produces empty string",
		},
		{
			name:     "empty new key produces empty string",
			key:      backend.NewKey(),
			expected: "",
		},
		{
			name:     "key with only empty string produces separator",
			key:      backend.NewKey(""),
			expected: "/",
		},
		{
			name:     "key with contents are separated",
			key:      backend.NewKey("foo", "bar", "baz", "quux"),
			expected: "/foo/bar/baz/quux",
		},
		{
			name:     "empty exact key produces separator",
			key:      backend.ExactKey(),
			expected: "/",
		},
		{
			name:     "empty string exact key produces double separator",
			key:      backend.ExactKey(""),
			expected: "//",
		},
		{
			name:     "exact key adds trailing separator",
			key:      backend.ExactKey("foo", "bar", "baz", "quux"),
			expected: "/foo/bar/baz/quux/",
		},
		{
			name:     "noendm key",
			key:      backend.Key{0},
			expected: "\x00",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, test.key.String())

		})
	}
}

func TestKeyScan(t *testing.T) {
	tests := []struct {
		name          string
		scan          any
		expectedError string
		expectedKey   backend.Key
	}{
		{
			name:          "invalid type int",
			scan:          123,
			expectedError: "invalid Key type int",
		},
		{
			name:          "invalid type bool",
			scan:          false,
			expectedError: "invalid Key type bool",
		},
		{
			name:        "empty string key",
			scan:        "",
			expectedKey: backend.Key{},
		},
		{
			name:        "empty byte slice key",
			scan:        []byte{},
			expectedKey: backend.Key{},
		},
		{
			name:        "populated string key",
			scan:        backend.NewKey("foo", "bar", "baz").String(),
			expectedKey: backend.NewKey("foo", "bar", "baz"),
		},
		{
			name:        "populated byte slice key",
			scan:        []byte(backend.NewKey("foo", "bar", "baz").String()),
			expectedKey: backend.NewKey("foo", "bar", "baz"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			k := new(backend.Key)
			err := k.Scan(test.scan)
			if test.expectedError == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, test.expectedError)
			}
			assert.Equal(t, test.expectedKey, *k)
		})
	}
}
