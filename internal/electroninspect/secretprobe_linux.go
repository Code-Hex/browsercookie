//go:build linux

package electroninspect

import (
	"errors"

	"github.com/Code-Hex/browsercookie/internal/browsercfg"
	"github.com/godbus/dbus/v5"
)

const linuxInspectDBusAppID = "browsercookie"

type linuxKeyringProber interface {
	HasSecret(schema, application string) (bool, error)
	HasKWalletEntry(folder, key string) (bool, error)
}

var newLinuxKeyringProber = func() (linuxKeyringProber, error) {
	conn, err := dbus.SessionBus()
	if err != nil {
		return nil, err
	}
	return &linuxDBusProber{conn: conn}, nil
}

type linuxDBusProber struct {
	conn *dbus.Conn
}

func probeSecretLocations(spec browsercfg.ChromiumSpec, _ []string) []Location {
	prober, err := newLinuxKeyringProber()
	if err != nil {
		return nil
	}

	var locations []Location
	for _, ref := range spec.LinuxLibsecretRefs("linux") {
		ok, err := prober.HasSecret(ref.Schema, ref.Application)
		if err != nil || !ok {
			continue
		}
		locations = append(locations, Location{
			Kind:   "safe_storage",
			Status: "present",
			Scope:  "app",
			Path:   ref.Schema + "/" + ref.Application,
			Format: "secret_ref",
			SecretRef: &SecretRef{
				Schema: ref.Schema,
				Name:   ref.Application,
			},
			Evidence: []string{"libsecret item exists"},
		})
	}
	for _, ref := range spec.LinuxKWalletRefs("linux") {
		ok, err := prober.HasKWalletEntry(ref.Folder, ref.Key)
		if err != nil || !ok {
			continue
		}
		locations = append(locations, Location{
			Kind:   "safe_storage",
			Status: "present",
			Scope:  "app",
			Path:   ref.Folder + "/" + ref.Key,
			Format: "secret_ref",
			SecretRef: &SecretRef{
				Folder: ref.Folder,
				Key:    ref.Key,
			},
			Evidence: []string{"kwallet entry exists"},
		})
	}
	return locations
}

func (p *linuxDBusProber) HasSecret(schema, application string) (bool, error) {
	attrs := map[string]string{
		"xdg:schema":  schema,
		"application": application,
	}

	service := p.conn.Object("org.freedesktop.secrets", "/org/freedesktop/secrets")
	var unlocked []dbus.ObjectPath
	var locked []dbus.ObjectPath
	if err := service.Call("org.freedesktop.Secret.Service.SearchItems", 0, attrs).Store(&unlocked, &locked); err != nil {
		return false, err
	}
	return len(unlocked) > 0 || len(locked) > 0, nil
}

func (p *linuxDBusProber) HasKWalletEntry(folder, key string) (bool, error) {
	for _, endpoint := range []struct {
		service string
		path    dbus.ObjectPath
	}{
		{service: "org.kde.kwalletd6", path: "/modules/kwalletd6"},
		{service: "org.kde.kwalletd5", path: "/modules/kwalletd5"},
	} {
		obj := p.conn.Object(endpoint.service, endpoint.path)

		var wallet string
		if err := obj.Call("org.kde.KWallet.networkWallet", 0).Store(&wallet); err != nil {
			continue
		}

		var handle int32
		if err := obj.Call("org.kde.KWallet.open", 0, wallet, int64(0), linuxInspectDBusAppID).Store(&handle); err != nil {
			continue
		}
		if handle < 0 {
			continue
		}

		var password string
		err := obj.Call("org.kde.KWallet.readPassword", 0, handle, folder, key, linuxInspectDBusAppID).Store(&password)
		_ = obj.Call("org.kde.KWallet.close", 0, wallet, false)
		if err == nil {
			return true, nil
		}
	}
	return false, errors.New("kwallet entry not found")
}
