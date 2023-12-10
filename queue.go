package tapprotocol

import "log/slog"

type Queue struct {
	elements []interface{}
}

func (q *Queue) Enqueue(element interface{}) {
	slog.Debug("Enqueue", "Command", element)
	q.elements = append(q.elements, element)
}

func (q *Queue) Dequeue() interface{} {
	if len(q.elements) == 0 {
		return nil
	}

	element := q.elements[0]
	q.elements = q.elements[1:]

	slog.Debug("Dequeue", "Command", element)
	return element
}

func (q *Queue) Peek() interface{} {
	if len(q.elements) == 0 {
		return nil
	}
	element := q.elements[0]
	slog.Debug("Peek", "Command", element)
	return element
}
func (q *Queue) Size() int {
	return len(q.elements)
}

func (q *Queue) IsEmpty() bool {
	return len(q.elements) == 0
}
