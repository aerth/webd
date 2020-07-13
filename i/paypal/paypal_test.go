package paypal

import (
	"bytes"
	"os"
	"strings"
	"testing"
	"text/template"
)

var testTemplate1 = `
{{ paypal "1001" "Iron Bucket" "A small cylindrical or conical container for holding and carrying small amounts of liquid such as water or lye. They are used by dwarves to give water to other dwarves, to store lye, and are required to build wells and certain workshops. They can be made of wood or metal." "20" }}
`

var testTemplate2 = `
Products:
{{ range .products }}
{{ .Link }}
{{ end }}

Done with products
`

func newTestTemplate(t *testing.T, templateText string) *template.Template {
	return template.Must(template.New("test").Funcs(template.FuncMap{"paypal": Paypal}).Parse(templateText))
}

func TestPaypalTemplate(t *testing.T) {
	if skip := os.Getenv("TEST_PAYPAL_TOKEN") == ""; skip {
		t.Skip("TEST_PAYPAL_TOKEN is empty")
	}
	if skip := os.Getenv("TEST_PAYPAL_KEY") == ""; skip {
		t.Skip("TEST_PAYPAL_KEY is empty")
	}
	RegisterToken(os.Getenv("TEST_PAYPAL_TOKEN"))
	RegisterKey(os.Getenv("TEST_PAYPAL_KEY"))
	buf := &bytes.Buffer{}
	tpl := newTestTemplate(t, testTemplate1)
	tpl.Execute(buf, nil)
	b := buf.Bytes()
	if !strings.Contains(string(b), "cylindrical") {
		t.Log("Cant find cylindrical:", string(b))
		t.FailNow()
	}
	os.Stdout.Write(b)
}

type Product struct {
	ID          string
	Name        string
	Description string
	Price       string
}

func (p Product) Link() string {
	return Paypal(p.ID, p.Name, p.Description, p.Price)
}

func TestPaypalTemplateRange(t *testing.T) {
	if skip := os.Getenv("TEST_PAYPAL_TOKEN") == ""; skip {
		t.Skip("TEST_PAYPAL_TOKEN is empty")
	}
	if skip := os.Getenv("TEST_PAYPAL_KEY") == ""; skip {
		t.Skip("TEST_PAYPAL_KEY is empty")
	}
	RegisterToken(os.Getenv("TEST_PAYPAL_TOKEN"))
	RegisterKey(os.Getenv("TEST_PAYPAL_KEY"))
	buf := &bytes.Buffer{}
	tpl := newTestTemplate(t, testTemplate2)
	err := tpl.Execute(buf, map[string]interface{}{
		"products": []Product{
			{"1002", "Steel Bucket", "This is a steel bucket", "50.00"},
			{"1003", "Aluminum Bucket", "This is an aluminum bucket", "20.00"},
		},
	})
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	b := buf.Bytes()
	if !strings.Contains(string(b), "aluminum") {
		t.Log("Cant find aluminum:", string(b))
		t.FailNow()
	}
	os.Stdout.Write(b)
}
