# negroni-auth-dynamodb [![Build Status](https://travis-ci.org/nabeken/negroni-auth.png?branch=master)](https://travis-ci.org/nabeken/negroni-auth)

Negroni middleware/handler for http basic authentication support DynamoDB forked from [nabeken/negroni-auth](https://github.com/nabeken/negroni-auth).

## Usage

~~~ go
import (
  "github.com/codegangsta/negroni"
  "github.com/anphung/negroni-auth"
)

func main() {
  m := negroni.New()
  // authenticate every request
  m.UseHandler(auth.BasicDynamoDB("basic_auth_table", "userid", "password"))
  m.Run()
}

~~~

## Authors

* [Jeremy Saenz](http://github.com/codegangsta)
* [Brendon Murphy](http://github.com/bemurphy)
* [nabeken](https://github.com/nabeken)
* [anphung](https://github.com/anphung)
