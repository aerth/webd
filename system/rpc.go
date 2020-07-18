package system

type RPC struct {
	parent *System
}

func (r *RPC) Foo(arg string, reply *string) error {
	*reply = "bar"
	return nil
}
