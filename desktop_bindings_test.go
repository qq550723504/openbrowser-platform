package main

import (
	"ant-chrome/backend"
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

func TestProductionDesktopBindingsHaveCompleteAdmissionPolicy(t *testing.T) {
	t.Setenv("ABFREE_OIDC_ISSUER", "")
	t.Setenv("ABFREE_OIDC_CLIENT_ID", "")
	app := NewApp(t.TempDir(), "binding-test")
	bindings := desktopBindings(app)
	if len(bindings) != 1 || bindings[0] != app {
		t.Fatal("unexpected production binding")
	}
	data, err := os.ReadFile("frontend/src/auth/bindings.json")
	if err != nil {
		t.Fatal(err)
	}
	var policy map[string]struct {
		Arguments int    `json:"arguments"`
		Policy    string `json:"policy"`
	}
	if err := json.Unmarshal(data, &policy); err != nil {
		t.Fatal(err)
	}
	typ := reflect.TypeOf(bindings[0])
	value := reflect.ValueOf(bindings[0])
	if typ.NumMethod() != len(policy) {
		t.Fatalf("binding inventory drift: %d methods vs %d policies", typ.NumMethod(), len(policy))
	}
	for i := 0; i < typ.NumMethod(); i++ {
		m := typ.Method(i)
		rule, ok := policy[m.Name]
		if !ok || m.Type.NumIn()-1 != rule.Arguments {
			t.Fatalf("unclassified/signature drift: %s", m.Name)
		}
		if rule.Policy != "protected" {
			continue
		}
		fn := value.Method(i)
		args := make([]reflect.Value, fn.Type().NumIn())
		for j := range args {
			args[j] = reflect.Zero(fn.Type().In(j))
		}
		out := fn.Call(args)
		last := out[len(out)-1].Interface()
		if last == nil {
			t.Fatalf("unconfigured production binding admitted %s", m.Name)
		}
	}
	coreType := reflect.TypeOf((*backend.App)(nil))
	for i := 0; i < coreType.NumMethod(); i++ {
		name := coreType.Method(i).Name
		if name == "GetInterceptor" {
			if _, ok := typ.MethodByName(name); ok {
				t.Fatal("internal getter bound")
			}
			continue
		}
		if _, ok := typ.MethodByName(name); !ok {
			t.Fatalf("original method missing classification: %s", name)
		}
	}
}
