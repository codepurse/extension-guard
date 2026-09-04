//go:build windows

package main

import (
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Removing the maximise button, and why it is done here rather than in the
// options block.
//
// Wails has no option for this. It drives the button from DisableResize:
//
//	result.EnableSizable(!appoptions.DisableResize)
//	result.EnableMaxButton(!appoptions.DisableResize)
//
// so the only supported way to grey the button also nails the window to
// exactly Width x Height. That is not a trade this app can make: the opening
// height is 860 and a 1366x768 laptop - still a common Windows resolution -
// would get a window taller than its screen with no way to shrink it, and no
// scrollbar can fix a title bar that is off the bottom.
//
// So the button is taken off the window itself. Clearing WS_MAXIMIZEBOX leaves
// minimise and close, and it covers the other three ways in as well: a
// double-click on the title bar, Win+Up, and the Maximize item in the system
// menu all stop maximising, because all four read the same style bit. Dragging
// the edges still works, bounded by MinWidth/MinHeight and MaxWidth/MaxHeight.

// GWL_STYLE is negative, and uintptr(gwlStyle) will not compile whether the
// constant is typed or not: a conversion of a constant is evaluated at compile
// time, where -16 does not fit an unsigned word. It has to reach the syscall
// through a function parameter instead, so the conversion happens at run time
// and sign-extends - which is what windowLong and setWindowLong below are for,
// and the only reason they exist.
const gwlStyle int32 = -16

const (
	wsMaximizeBox  = 0x00010000
	swpNoSize      = 0x0001
	swpNoMove      = 0x0002
	swpNoZOrder    = 0x0004
	swpNoActivate  = 0x0010
	swpFrameChange = 0x0020
	gwOwner        = 4
)

var (
	user32                       = windows.NewLazySystemDLL("user32.dll")
	procEnumWindows              = user32.NewProc("EnumWindows")
	procGetWindowThreadProcessID = user32.NewProc("GetWindowThreadProcessId")
	procGetWindowLongPtr         = user32.NewProc("GetWindowLongPtrW")
	procSetWindowLongPtr         = user32.NewProc("SetWindowLongPtrW")
	procSetWindowPos             = user32.NewProc("SetWindowPos")
	procIsWindowVisible          = user32.NewProc("IsWindowVisible")
	procGetWindow                = user32.NewProc("GetWindow")
)

// mainWindow finds this process's own top-level window.
//
// Wails does not hand out the HWND, so it is looked up rather than asked for:
// the one visible, unowned, top-level window belonging to this process id. The
// unowned test is what skips the dialogs and the WebView2 host windows, which
// are children or owned popups; the visible test is what skips the message-only
// windows Wails and WebView2 both create.
func mainWindow() windows.HWND {
	me := uint32(windows.Getpid())
	var found windows.HWND

	cb := syscall.NewCallback(func(hwnd windows.HWND, _ uintptr) uintptr {
		var pid uint32
		procGetWindowThreadProcessID.Call(uintptr(hwnd), uintptr(unsafe.Pointer(&pid)))
		if pid != me {
			return 1 // keep going
		}
		if visible, _, _ := procIsWindowVisible.Call(uintptr(hwnd)); visible == 0 {
			return 1
		}
		if owner, _, _ := procGetWindow.Call(uintptr(hwnd), gwOwner); owner != 0 {
			return 1
		}
		found = hwnd
		return 0 // stop
	})

	procEnumWindows.Call(cb, 0)
	return found
}

// disableMaximise clears WS_MAXIMIZEBOX on this process's window.
//
// It retries, in the background, because the one thing it depends on is timing
// it does not control: DomReady says the page has loaded, not that the frame
// has been shown, and mainWindow only matches a window that is already
// visible. Ten tries over a second costs nothing and removes the guesswork.
//
// Every failure is silent. If the lookup never matches - a future Wails that
// owns its top-level window differently, say - the app simply opens with a
// maximise button, which still cannot exceed MaxWidth/MaxHeight. A caption
// button is not worth a startup error path, and OnDomReady has nowhere to
// report one to.
func disableMaximise() {
	go func() {
		for i := 0; i < 10; i++ {
			if tryDisableMaximise() {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
	}()
}

// tryDisableMaximise reports whether the style bit is now off - which counts
// as done whether this call cleared it or found it already clear.
func tryDisableMaximise() bool {
	hwnd := mainWindow()
	if hwnd == 0 {
		return false
	}
	style := windowLong(hwnd, gwlStyle)
	if style == 0 {
		return false // the call failed; try again
	}
	if style&wsMaximizeBox == 0 {
		return true // already off
	}
	setWindowLong(hwnd, gwlStyle, style&^wsMaximizeBox)
	// The frame is already drawn, so Windows has to be told to redraw the
	// caption buttons; without SWP_FRAMECHANGED the button stays on screen and
	// stays clickable until something else invalidates the non-client area.
	procSetWindowPos.Call(uintptr(hwnd), 0, 0, 0, 0, 0,
		swpNoSize|swpNoMove|swpNoZOrder|swpNoActivate|swpFrameChange)
	return windowLong(hwnd, gwlStyle)&wsMaximizeBox == 0
}

// windowLong and setWindowLong exist only so the negative index reaches the
// syscall as a runtime conversion. Taking it as an int32 parameter is what
// makes uintptr(index) sign-extend instead of failing to compile.
func windowLong(hwnd windows.HWND, index int32) uintptr {
	v, _, _ := procGetWindowLongPtr.Call(uintptr(hwnd), uintptr(index))
	return v
}

func setWindowLong(hwnd windows.HWND, index int32, value uintptr) {
	procSetWindowLongPtr.Call(uintptr(hwnd), uintptr(index), value)
}
