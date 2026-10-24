package main

import (
	"encoding/json"
	"fmt"
	"image/color"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
)

var probePorts = []int{22, 135, 139, 445, 3389, 5357, 7680, 515, 631, 8009, 9100, 62078}

var phoneHints = []string{"iphone", "ipad", "android", "galaxy", "pixel", "oneplus", "xiaomi", "redmi", "huawei", "oppo", "motorola"}
var pcHints = []string{"desktop", "laptop", "pc", "macbook", "windows", "thinkpad", "dell", "lenovo", "asus", "intel", "hewlett", "microsoft"}

var vendorKinds = []struct {
	kind string
	keys []string
}{
	{"router/network", []string{"commscope", "actiontec", "arcadyan", "netgear", "tp-link", "ubiquiti", "cisco", "technicolor", "sagemcom"}},
	{"IoT/smart device", []string{"espressif", "icomm", "amazon", "bsh hausger", "tuya", "sonos", "philips lighting", "ecobee"}},
	{"TV/streaming", []string{"roku", "sei robotics", "vizio", "tcl", "hisense"}},
}

// Your own device names, keyed by MAC. Saved to %AppData%\NetScanner\known_devices.json
var (
	knownDevices = map[string]string{}
	knownMu      sync.RWMutex
)

func normMAC(mac string) string {
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(mac), ":", "-"))
}

func knownPath() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "known_devices.json"
	}
	dir = filepath.Join(dir, "NetScanner")
	os.MkdirAll(dir, 0o755)
	return filepath.Join(dir, "known_devices.json")
}

func loadKnown() {
	data, err := os.ReadFile(knownPath())
	if err != nil {
		return
	}
	knownMu.Lock()
	json.Unmarshal(data, &knownDevices)
	knownMu.Unlock()
}

func saveKnown() {
	knownMu.RLock()
	data, _ := json.MarshalIndent(knownDevices, "", "  ")
	knownMu.RUnlock()
	os.WriteFile(knownPath(), data, 0o644)
}

// An empty name removes the entry.
func setKnown(mac, name string) {
	mac = normMAC(mac)
	knownMu.Lock()
	if name == "" {
		delete(knownDevices, mac)
	} else {
		knownDevices[mac] = name
	}
	knownMu.Unlock()
	saveKnown()
}

func getKnown(mac string) (string, bool) {
	knownMu.RLock()
	defer knownMu.RUnlock()
	name, ok := knownDevices[normMAC(mac)]
	return name, ok
}

func sortedKnownMACs() []string {
	knownMu.RLock()
	defer knownMu.RUnlock()
	macs := make([]string, 0, len(knownDevices))
	for m := range knownDevices {
		macs = append(macs, m)
	}
	sort.Strings(macs)
	return macs
}

type Device struct {
	IP, MAC, Host, Vendor, Kind string
	Random, Self                bool
	Ports                       map[int]bool
}

func localIP() net.IP {
	conn, err := net.Dial("udp", "8.8.8.8:80") // sends no packets, just picks the local interface
	if err != nil {
		return nil
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.To4()
}

func detectPrefix() string {
	ip := localIP()
	if ip == nil {
		return "192.168.1."
	}
	return fmt.Sprintf("%d.%d.%d.", ip[0], ip[1], ip[2])
}

// Builds a Device entry for this PC by matching its IP to a network adapter.
func selfDevice(prefix string) *Device {
	ip := localIP()
	if ip == nil || !strings.HasPrefix(ip.String(), prefix) {
		return nil
	}
	ifaces, _ := net.Interfaces()
	for _, ifc := range ifaces {
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.Equal(ip) {
				mac := strings.ReplaceAll(ifc.HardwareAddr.String(), ":", "-")
				host, _ := os.Hostname()
				return &Device{
					IP: ip.String(), MAC: mac, Host: host,
					Random: isRandomMAC(mac), Ports: map[int]bool{}, Self: true,
				}
			}
		}
	}
	return nil
}

// Touch every IP so Windows sends ARP requests, even if the connection is refused.
func sweep(prefix string) {
	var wg sync.WaitGroup
	for i := 1; i < 255; i++ {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			conn, err := net.DialTimeout("tcp", ip+":80", 500*time.Millisecond)
			if err == nil {
				conn.Close()
			}
		}(fmt.Sprintf("%s%d", prefix, i))
	}
	wg.Wait()
}

func readARP(prefix string) []*Device {
	cmd := exec.Command("arp", "-a")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000} // no console flash
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	var devices []*Device
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[2] != "dynamic" || !strings.HasPrefix(fields[0], prefix) {
			continue
		}
		devices = append(devices, &Device{
			IP:     fields[0],
			MAC:    fields[1],
			Random: isRandomMAC(fields[1]),
			Ports:  map[int]bool{},
		})
	}
	return devices
}

// Randomized (privacy) MACs have the "locally administered" bit set.
func isRandomMAC(mac string) bool {
	if len(mac) < 2 {
		return false
	}
	b, err := strconv.ParseUint(mac[:2], 16, 8)
	return err == nil && b&0x02 != 0
}

func portOpen(ip string, port int) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), 400*time.Millisecond)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func lookupVendor(mac string) string {
	client := http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("https://api.macvendors.com/" + strings.ReplaceAll(mac, "-", ":"))
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return ""
	}
	body, _ := io.ReadAll(resp.Body)
	return strings.TrimSpace(string(body))
}

func hasAny(text string, hints []string) bool {
	for _, h := range hints {
		if strings.Contains(text, h) {
			return true
		}
	}
	return false
}

func classify(d *Device) string {
	text := strings.ToLower(d.Host + " " + d.Vendor)
	switch {
	case d.Ports[62078]:
		return "phone (iOS)"
	case d.Ports[9100] || d.Ports[631] || d.Ports[515] || strings.Contains(text, "brw"):
		return "printer"
	case d.Ports[8009]:
		return "cast/TV"
	case d.Ports[135] || d.Ports[3389] || d.Ports[5357] || d.Ports[7680]:
		return "computer (Windows)"
	case d.Ports[22]:
		return "computer/server"
	case d.Ports[139] || d.Ports[445]:
		return "computer/NAS (file sharing)"
	}
	for _, vk := range vendorKinds {
		if hasAny(text, vk.keys) {
			return vk.kind
		}
	}
	switch {
	case hasAny(text, phoneHints):
		return "phone"
	case hasAny(text, pcHints):
		return "computer"
	case d.Random:
		return "phone? (random MAC)"
	}
	return "unknown"
}

func label(d *Device) string {
	name, known := getKnown(d.MAC)
	switch {
	case d.Self && known:
		return "Your device (" + name + ")"
	case d.Self:
		return "Your device"
	case known:
		return name
	}
	return classify(d)
}

func main() {
	loadKnown()

	a := app.New()
	w := a.NewWindow("Network Scanner")
	w.Resize(fyne.NewSize(960, 520))

	headers := []string{"IP", "MAC", "Type", "Hostname", "Vendor"}
	widths := []float32{130, 150, 180, 170, 260}
	var devices []*Device // only touched on the UI thread
	selected := 0         // selected table row; 0 is the header, meaning nothing selected

	gold := color.NRGBA{R: 255, G: 193, B: 7, A: 120}

	table := widget.NewTable(
		func() (int, int) { return len(devices) + 1, len(headers) },
		func() fyne.CanvasObject {
			bg := canvas.NewRectangle(color.Transparent)
			l := widget.NewLabel("template")
			l.Truncation = fyne.TextTruncateEllipsis
			return container.NewStack(bg, l)
		},
		func(id widget.TableCellID, o fyne.CanvasObject) {
			stack := o.(*fyne.Container)
			bg := stack.Objects[0].(*canvas.Rectangle)
			l := stack.Objects[1].(*widget.Label)
			bg.FillColor = color.Transparent
			if id.Row == 0 {
				bg.Refresh()
				l.TextStyle = fyne.TextStyle{Bold: true}
				l.SetText(headers[id.Col])
				return
			}
			d := devices[id.Row-1]
			if d.Self {
				bg.FillColor = gold
			}
			bg.Refresh()
			l.TextStyle = fyne.TextStyle{Bold: d.Self}
			l.SetText([]string{d.IP, d.MAC, d.Kind, d.Host, d.Vendor}[id.Col])
		},
	)
	for i, wd := range widths {
		table.SetColumnWidth(i, wd)
	}
	table.OnSelected = func(id widget.TableCellID) { selected = id.Row }

	// Re-apply names to every device and redraw.
	refresh := func() {
		for _, d := range devices {
			d.Kind = label(d)
		}
		table.Refresh()
	}

	// --- Devices menu ---
	nameSelected := fyne.NewMenuItem("Name selected device...", func() {
		if selected < 1 || selected > len(devices) {
			dialog.ShowInformation("No device selected", "Click a row in the table first.", w)
			return
		}
		d := devices[selected-1]
		if d.MAC == "" {
			dialog.ShowInformation("Can't name this device", "No MAC address was found for it.", w)
			return
		}
		current, _ := getKnown(d.MAC)
		nameEntry := widget.NewEntry()
		nameEntry.SetText(current)
		nameEntry.SetPlaceHolder("e.g. Dad's phone (leave empty to remove)")
		dialog.ShowForm("Name device", "Save", "Cancel",
			[]*widget.FormItem{
				widget.NewFormItem("MAC", widget.NewLabel(d.MAC)),
				widget.NewFormItem("Name", nameEntry),
			},
			func(ok bool) {
				if !ok {
					return
				}
				setKnown(d.MAC, strings.TrimSpace(nameEntry.Text))
				refresh()
			}, w)
	})

	addManual := fyne.NewMenuItem("Add device by MAC...", func() {
		macEntry := widget.NewEntry()
		macEntry.SetPlaceHolder("aa-bb-cc-dd-ee-ff")
		nameEntry := widget.NewEntry()
		dialog.ShowForm("Add known device", "Add", "Cancel",
			[]*widget.FormItem{
				widget.NewFormItem("MAC", macEntry),
				widget.NewFormItem("Name", nameEntry),
			},
			func(ok bool) {
				if !ok {
					return
				}
				name := strings.TrimSpace(nameEntry.Text)
				if _, err := net.ParseMAC(strings.TrimSpace(macEntry.Text)); err != nil || name == "" {
					dialog.ShowError(fmt.Errorf("enter a valid MAC address and a name"), w)
					return
				}
				setKnown(macEntry.Text, name)
				refresh()
			}, w)
	})

	manage := fyne.NewMenuItem("Manage known devices...", func() {
		macs := sortedKnownMACs()
		if len(macs) == 0 {
			dialog.ShowInformation("Known devices", "No known devices yet.", w)
			return
		}
		sel := -1
		list := widget.NewList(
			func() int { return len(macs) },
			func() fyne.CanvasObject { return widget.NewLabel("template") },
			func(i widget.ListItemID, o fyne.CanvasObject) {
				name, _ := getKnown(macs[i])
				o.(*widget.Label).SetText(macs[i] + "   ->   " + name)
			},
		)
		list.OnSelected = func(id widget.ListItemID) { sel = id }
		remove := widget.NewButton("Remove selected", func() {
			if sel < 0 || sel >= len(macs) {
				return
			}
			setKnown(macs[sel], "")
			macs = append(macs[:sel], macs[sel+1:]...)
			sel = -1
			list.UnselectAll()
			list.Refresh()
			refresh()
		})
		dlg := dialog.NewCustom("Known devices", "Close", container.NewBorder(nil, remove, nil, nil, list), w)
		dlg.Resize(fyne.NewSize(520, 360))
		dlg.Show()
	})

	w.SetMainMenu(fyne.NewMainMenu(fyne.NewMenu("Devices", nameSelected, addManual, manage)))

	// --- Scan controls ---
	prefixEntry := widget.NewEntry()
	prefixEntry.SetText(detectPrefix())
	status := widget.NewLabel("Ready. Press Scan. To name a device, click its row, then Devices > Name selected device.")

	var scanBtn *widget.Button
	scanBtn = widget.NewButton("Scan", func() {
		prefix := strings.TrimSpace(prefixEntry.Text)
		if !strings.HasSuffix(prefix, ".") {
			prefix += "."
		}
		scanBtn.Disable()
		status.SetText("Scanning network...")

		go func() {
			sweep(prefix)
			found := readARP(prefix)

			// Add this PC (arp -a never lists it), always first in the table.
			if me := selfDevice(prefix); me != nil {
				list := []*Device{me}
				for _, d := range found {
					if d.IP != me.IP {
						list = append(list, d)
					}
				}
				found = list
			}
			fyne.Do(func() { status.SetText(fmt.Sprintf("Found %d devices, probing ports...", len(found))) })

			var wg sync.WaitGroup
			for _, d := range found {
				wg.Add(1)
				go func(d *Device) {
					defer wg.Done()
					if d.Self {
						return // no need to probe our own PC
					}
					if names, err := net.LookupAddr(d.IP); err == nil && len(names) > 0 {
						d.Host = strings.TrimSuffix(names[0], ".")
					}
					for _, p := range probePorts {
						d.Ports[p] = portOpen(d.IP, p)
					}
				}(d)
			}
			wg.Wait()
			for _, d := range found {
				d.Kind = label(d)
			}

			fyne.Do(func() {
				devices = found
				selected = 0
				table.UnselectAll()
				table.Refresh()
				status.SetText("Looking up vendors...")
			})

			// Vendor lookups fill in one by one (free API allows ~1 request/second).
			for _, d := range found {
				if d.Random || d.MAC == "" {
					continue
				}
				d := d
				v := lookupVendor(d.MAC)
				time.Sleep(1100 * time.Millisecond)
				fyne.Do(func() {
					d.Vendor = v
					d.Kind = label(d)
					table.Refresh()
				})
			}

			fyne.Do(func() {
				status.SetText(fmt.Sprintf("Done. %d devices found.", len(found)))
				scanBtn.Enable()
			})
		}()
	})

	top := container.NewBorder(nil, nil, widget.NewLabel("Subnet:"), scanBtn, prefixEntry)
	w.SetContent(container.NewBorder(top, status, nil, nil, table))
	w.ShowAndRun()
}
