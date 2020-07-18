package paypal

import (
	"fmt"
	"log"
	"os"
	"strings"

	paypalapi "github.com/plutov/paypal/v3"
)

var paypalcreds = struct{ token, key string }{
	token: "",
	key:   "",
}

func RegisterToken(s string) {
	paypalcreds.token = s
}

func RegisterKey(s string) {
	paypalcreds.key = s
}

func Paypal(s ...string) string {
	if len(s) != 4 || paypalcreds.token == "" || paypalcreds.key == "" {
		log.Printf("%d != 4 or token unset", len(s))
		return "error: see log (1)"
	}
	str := strings.Builder{}
	id, name, desc, price := s[0], s[1], s[2], s[3]
	fmt.Fprintf(&str, "%s: %q - %s (%s)", id, name, desc, price)
	apibase := paypalapi.APIBaseSandBox
	c, err := paypalapi.NewClient(paypalcreds.token, paypalcreds.key, apibase)
	if err != nil {
		log.Println(err)
		return "error: see log (2)"
	}
	c.SetLog(os.Stdout) // Set log to terminal stdout
	accessToken, err := c.GetAccessToken()
	if err != nil {
		log.Println(err)
		return "error: see log (3)"
	}

	_ = accessToken
	return str.String()
}

var HTMLApprove = `
<div id="paypal-button-container"></div>
<script src="https://www.paypalobjects.com/api/checkout.js"></script>
<script>
paypal.Button.render({

	env: 'sandbox', /* sandbox | production */

	/* Show the buyer a 'Pay Now' button in the checkout flow */
	commit: true,

	/* payment() is called when the button is clicked */
	payment: function() {

		/* Set up a url on your server to create the payment */
		var CREATE_URL = '/i/paypal/create';

		/* Make a call to your server to set up the payment */
		return paypal.request.post(CREATE_URL)
			.then(function({response}) {
				return response.body.id;
			});
	},

	/* onAuthorize() is called when the buyer approves the payment */
	onAuthorize: function(data, actions) {

		/* Set up a url on your server to execute the payment */
		var EXECUTE_URL = '/i/paypal/execute';

		/* Set up the data you need to pass to your server */
		var data = {
			paymentID: data.paymentID,
			payerID: data.payerID
		};

		/* Make a call to your server to execute the payment */
		return paypal.request.post(EXECUTE_URL, data)
			.then(function (res) {
				window.alert('Payment Complete!');
			});
	}

}, '#paypal-button-container');
</script>
`
