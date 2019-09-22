import io.ktor.client.HttpClient
import io.ktor.client.request.headers
import io.ktor.client.request.request
import io.ktor.client.request.url
import io.ktor.http.HttpMethod

suspend fun download(url: String, client: HttpClient, reqBody: String = "") = client.request<String> {
  headers {
    append(
            "User-Agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.132 Safari/537.36"
    )
  }
  url(url)
  method = HttpMethod.Get
  body = reqBody
}