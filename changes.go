package facetfs

type ChangeKind uint8

const (
	ChangeCreated ChangeKind = iota + 1
	ChangeData
	ChangeMetadata
	ChangeNamespace
	ChangeRemoved
)

type ChangeEvent struct {
	Kind      ChangeKind
	Object    ObjectRef
	Parent    ObjectRef
	NewParent ObjectRef
	Offset    uint64
	Length    uint64
}

func (s *Server) SubscribeChanges(buffer int) (<-chan ChangeEvent, func()) {
	return s.changes.Subscribe(buffer)
}

func (s *Server) changed(event ChangeEvent) {
	s.changes.Publish(event)
}
