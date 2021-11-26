# JSON

Category: Web

> We have found an internal system that is externally exposed. Retrieve the Flag from this system.

Anyway, a few go files are provided:

`bff/main.go`

```go
type Info struct {
	ID int `json:"id" binding:"required"`
}

// check if the accessed user is in the local network (192.168.111.0/24)
func checkLocal() gin.HandlerFunc {
	// removed for brevity
}

func main() {
	r := gin.Default()
	r.Use(checkLocal())
	r.LoadHTMLGlob("templates/*")

	r.GET("/", func(c *gin.Context) {
		c.HTML(200, "index.html", nil)
	})

	r.POST("/", func(c *gin.Context) {
		// get request body
		body, err := ioutil.ReadAll(c.Request.Body)
		// parse json
		var info Info
		if err := json.Unmarshal(body, &info); err != nil {
			c.JSON(400, gin.H{"error": "Invalid parameter."})
			return
		}
		// validation
		if info.ID < 0 || info.ID > 2 {
			c.JSON(400, gin.H{"error": "ID must be an integer between 0 and 2."})
			return
		}
		if info.ID == 2 {
			c.JSON(400, gin.H{"error": "It is forbidden to retrieve Flag from this BFF server."})
			return
		}
		// get data from api server
		req, err := http.NewRequest("POST", "http://api:8000", bytes.NewReader(body))
		if err != nil {
			c.JSON(400, gin.H{"error": "Failed to request API."})
			return
		}
		req.Header.Set("Content-Type", "application/json")
		client := new(http.Client)
		resp, err := client.Do(req)
		defer resp.Body.Close()
		result, err := ioutil.ReadAll(resp.Body)
		c.JSON(200, gin.H{"result": string(result)})
	})

	if err := r.Run(":8080"); err != nil {
		panic("server is not started")
	}
}

```

`api/main.go`

```go
func main() {
	r := gin.Default()
	r.POST("/", func(c *gin.Context) {
		body, err := ioutil.ReadAll(c.Request.Body)
		id, err := jsonparser.GetInt(body, "id")
		if err != nil {
			c.String(400, "Failed to parse json")
			return
		}
		if id == 2 {
			// Flag!!!
			flag := os.Getenv("FLAG")
			c.String(200, flag)
			return
		}

		c.String(400, "No data")
	})

	if err := r.Run(":8000"); err != nil {
		panic("server is not started")
	}
}
```

The first challenge we need to overcome is the `checkLocal()` check. It doesn't seem we can use the SSRF attack in the previous challenge here. Maybe we can use something else?

## `X-forwarded-for` header

The [X-Forwarded-For](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Forwarded-For) header is used by proxies to specify the originating IP address. By spoofing this address in postman, we can get past the first check.

## JSON parameter pollution??

Next, the application reads JSON body and checks that the `id` parameter is between 0 and 2 (inclusive). However, if `id==2`, it returns with an error message. Unfortunately, we need to set `id==2` to get the flag in `api/main.go`. I wasn't sure what to do here, but an application with 2 APIs seems to point toward HTTP parameter pollution, where a HTTP parameter is specified twice, and each API parses it differently. Could JSON also be vulnerable to such an attack?

Let's look at how the JSON body is parsed in each API:

`bff/main.go`

```go
json.Unmarshal(body, &info)
```

I couldn't find any information about how `json.Unmarshal` handles duplicate keys

`api/main.go`

```go
jsonparser.GetInt(body, "id")
```

Hmm, definitely interesting! I also couldn't find out how this handles duplicate keys. I guess we'll just have to try both ways.

Luckily, this payload worked:

```json
{
    "id":2,
    "id":0
}
```

I suppose `json.Unmarshal` takes the second `id`, while `jsonparser` picks up the first one.

`Flag: ctf4b{j50n_is_v4ry_u5efu1_bu7_s0metim3s_it_bi7es_b4ck}`

