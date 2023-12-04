package tapprotocol

// Stack represents a stack data structure
type Stack struct {
	elements []string
}

// Push adds an element to the top of the stack
func (s *Stack) Push(value string) {
	s.elements = append(s.elements, value)
}

// Pop removes and returns the top element of the stack
func (s *Stack) Pop() (string, bool) {
	if len(s.elements) == 0 {
		return "", false
	}
	index := len(s.elements) - 1
	element := s.elements[index]
	s.elements = s.elements[:index]
	return element, true
}

// Peek returns the top element of the stack without removing it
func (s *Stack) Peek() (string, bool) {
	if len(s.elements) == 0 {
		return "", false
	}
	return s.elements[len(s.elements)-1], true
}

// IsEmpty returns true if the stack is empty
func (s *Stack) IsEmpty() bool {
	return len(s.elements) == 0
}
