package transport

const (
	DefaultQUICInitialStreamWindow     uint64 = 512 << 10
	DefaultQUICInitialConnectionWindow uint64 = 512 << 10
	DefaultQUICMaxStreamWindow         uint64 = 8 << 20
	DefaultQUICMaxConnectionWindow     uint64 = 12 << 20
)

// QUICOptions configures flow-control windows for a QUICHub.
// Zero fields use the defaults (8 MiB stream / 12 MiB connection max, 512 KiB initial).
type QUICOptions struct {
	InitialStreamReceiveWindow     uint64
	MaxStreamReceiveWindow         uint64
	InitialConnectionReceiveWindow uint64
	MaxConnectionReceiveWindow     uint64
}

func (o QUICOptions) normalize() QUICOptions {
	if o.MaxStreamReceiveWindow == 0 {
		o.MaxStreamReceiveWindow = DefaultQUICMaxStreamWindow
	}
	if o.MaxConnectionReceiveWindow == 0 {
		o.MaxConnectionReceiveWindow = DefaultQUICMaxConnectionWindow
	}
	if o.MaxConnectionReceiveWindow < o.MaxStreamReceiveWindow {
		o.MaxConnectionReceiveWindow = o.MaxStreamReceiveWindow
	}
	if o.InitialStreamReceiveWindow == 0 {
		o.InitialStreamReceiveWindow = DefaultQUICInitialStreamWindow
	}
	if o.InitialStreamReceiveWindow > o.MaxStreamReceiveWindow {
		o.InitialStreamReceiveWindow = o.MaxStreamReceiveWindow
	}
	if o.InitialConnectionReceiveWindow == 0 {
		o.InitialConnectionReceiveWindow = DefaultQUICInitialConnectionWindow
	}
	if o.InitialConnectionReceiveWindow > o.MaxConnectionReceiveWindow {
		o.InitialConnectionReceiveWindow = o.MaxConnectionReceiveWindow
	}
	return o
}
