package modules

import (
	"github.com/jayofelony/bettercap/modules/any_proxy"
	"github.com/jayofelony/bettercap/modules/api_rest"
	"github.com/jayofelony/bettercap/modules/arp_spoof"
	"github.com/jayofelony/bettercap/modules/ble"
	"github.com/jayofelony/bettercap/modules/c2"
	"github.com/jayofelony/bettercap/modules/caplets"
	"github.com/jayofelony/bettercap/modules/dhcp6_spoof"
	"github.com/jayofelony/bettercap/modules/dns_spoof"
	"github.com/jayofelony/bettercap/modules/events_stream"
	"github.com/jayofelony/bettercap/modules/gps"
	"github.com/jayofelony/bettercap/modules/hid"
	"github.com/jayofelony/bettercap/modules/http_proxy"
	"github.com/jayofelony/bettercap/modules/http_server"
	"github.com/jayofelony/bettercap/modules/https_proxy"
	"github.com/jayofelony/bettercap/modules/https_server"
	"github.com/jayofelony/bettercap/modules/mac_changer"
	"github.com/jayofelony/bettercap/modules/mdns_server"
	"github.com/jayofelony/bettercap/modules/mysql_server"
	"github.com/jayofelony/bettercap/modules/ndp_spoof"
	"github.com/jayofelony/bettercap/modules/net_probe"
	"github.com/jayofelony/bettercap/modules/net_recon"
	"github.com/jayofelony/bettercap/modules/net_sniff"
	"github.com/jayofelony/bettercap/modules/packet_proxy"
	"github.com/jayofelony/bettercap/modules/syn_scan"
	"github.com/jayofelony/bettercap/modules/tcp_proxy"
	"github.com/jayofelony/bettercap/modules/ticker"
	"github.com/jayofelony/bettercap/modules/ui"
	"github.com/jayofelony/bettercap/modules/update"
	"github.com/jayofelony/bettercap/modules/wifi"
	"github.com/jayofelony/bettercap/modules/wol"

	"github.com/jayofelony/bettercap/session"
)

func LoadModules(sess *session.Session) {
	sess.Register(any_proxy.NewAnyProxy(sess))
	sess.Register(arp_spoof.NewArpSpoofer(sess))
	sess.Register(api_rest.NewRestAPI(sess))
	sess.Register(ble.NewBLERecon(sess))
	sess.Register(dhcp6_spoof.NewDHCP6Spoofer(sess))
	sess.Register(net_recon.NewDiscovery(sess))
	sess.Register(dns_spoof.NewDNSSpoofer(sess))
	sess.Register(events_stream.NewEventsStream(sess))
	sess.Register(gps.NewGPS(sess))
	sess.Register(http_proxy.NewHttpProxy(sess))
	sess.Register(http_server.NewHttpServer(sess))
	sess.Register(https_proxy.NewHttpsProxy(sess))
	sess.Register(https_server.NewHttpsServer(sess))
	sess.Register(mac_changer.NewMacChanger(sess))
	sess.Register(mysql_server.NewMySQLServer(sess))
	sess.Register(mdns_server.NewMDNSServer(sess))
	sess.Register(net_sniff.NewSniffer(sess))
	sess.Register(packet_proxy.NewPacketProxy(sess))
	sess.Register(net_probe.NewProber(sess))
	sess.Register(syn_scan.NewSynScanner(sess))
	sess.Register(tcp_proxy.NewTcpProxy(sess))
	sess.Register(ticker.NewTicker(sess))
	sess.Register(wifi.NewWiFiModule(sess))
	sess.Register(wol.NewWOL(sess))
	sess.Register(hid.NewHIDRecon(sess))
	sess.Register(c2.NewC2(sess))
	sess.Register(ndp_spoof.NewNDPSpoofer(sess))

	sess.Register(caplets.NewCapletsModule(sess))
	sess.Register(update.NewUpdateModule(sess))
	sess.Register(ui.NewUIModule(sess))
}
