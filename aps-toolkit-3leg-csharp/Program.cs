using System.Diagnostics;
using System.Net;
using System.Text;
using Newtonsoft.Json;

var clientId = Environment.GetEnvironmentVariable("APS_CLIENT_ID");
var clientSecret = Environment.GetEnvironmentVariable("APS_CLIENT_SECRET");
Auth auth = new Auth(clientId, clientSecret);
var callBackUrl = "http://localhost:8080/api/auth/callback";
var scopes = "data:read data:write data:create data:search bucket:create bucket:read bucket:update bucket:delete code:all";
var token = await auth.Auth3Leg(callBackUrl, scopes);
Console.WriteLine("Authentication successful.");
Console.WriteLine($"Refresh token: {token.refresh_token}");
Console.WriteLine($"Expires In: {token.expires_in}");

public class Auth
{
    private readonly string client_id;
    private readonly string client_secret;
    private string access_token;
    private string token_type;
    private int expires_in;
    private string refresh_token;

    public Auth(string clientId, string clientSecret)
    {
        client_id = clientId;
        client_secret = clientSecret;
    }

    public async Task<Token> Auth3Leg(string callbackUrl = null, string scopes = null)
    {
        if (string.IsNullOrEmpty(scopes))
        {
            scopes =
                "data:read data:write data:create data:search bucket:create bucket:read bucket:update bucket:delete code:all";
        }

        if (string.IsNullOrEmpty(callbackUrl))
        {
            callbackUrl = "http://localhost:8080/api/auth/callback";
        }

        OpenDefaultBrowser(GetAuthUrl(callbackUrl, scopes));

        // Start listening for the callback URL
        var listenerTask = StartListener(callbackUrl);
        await listenerTask;

        return new Token(access_token, token_type, expires_in, refresh_token);
    }

    private string GetAuthUrl(string callbackUrl, string scopes)
    {
        return $"https://developer.api.autodesk.com/authentication/v2/authorize?response_type=code&client_id={client_id}&redirect_uri={callbackUrl}&scope={scopes}";
    }

    private void OpenDefaultBrowser(string url)
    {
        try
        {
            // Use the default browser on the system to open the URL
            Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
        }
        catch (Exception ex)
        {
            // Handle any exceptions, such as if there's no default browser set
            Console.WriteLine($"Error opening default browser: {ex.Message}");
        }
    }

    private async Task<Token> StartListener(string callbackUrl)
    {
        var listener = new HttpListener();
        listener.Prefixes.Add(callbackUrl + "/");
        listener.Start();

        Console.WriteLine($"Listening for callback at: {callbackUrl}");

        while (true)
        {
            var context = await listener.GetContextAsync();
            var request = context.Request;
            var response = context.Response;

            // Extract code from callback URL
            var query = request.Url.Query;
            var queryParams = System.Web.HttpUtility.ParseQueryString(query);
            var code = queryParams["code"];

            var resultToken = await HandleCallback(callbackUrl, code);
            access_token = resultToken.access_token;
            token_type = resultToken.token_type;
            expires_in = resultToken.expires_in;
            refresh_token = resultToken.refresh_token;

            var responseString = "Authentication successful. You can close this window now.";
            var buffer = System.Text.Encoding.UTF8.GetBytes(responseString);
            response.ContentLength64 = buffer.Length;
            await response.OutputStream.WriteAsync(buffer, 0, buffer.Length);
            response.Close();

            break;
        }

        listener.Stop();

        return new Token(access_token, token_type, expires_in, refresh_token);
    }

    private async Task<Token> HandleCallback(string callbackUrl, string code)
    {
        var tokenUrl = "https://developer.api.autodesk.com/authentication/v2/token";
        var payload = $"grant_type=authorization_code&code={code}&client_id={client_id}&client_secret={client_secret}&redirect_uri={callbackUrl}";

        using (var client = new HttpClient())
        {
            var content = new StringContent(payload, Encoding.UTF8, "application/x-www-form-urlencoded");
            var response = await client.PostAsync(tokenUrl, content);

            if (!response.IsSuccessStatusCode)
            {
                var errorMessage = await response.Content.ReadAsStringAsync();
                throw new Exception($"Failed to retrieve token: {errorMessage}");
            }

            var jsonResponse = await response.Content.ReadAsStringAsync();
            var resultToken = ParseToken(jsonResponse);
            return resultToken;
        }
    }
    private Token ParseToken(string json)
    {
        var token = JsonConvert.DeserializeObject<Token>(json);
        return token;
    }

}

public class Token
{
    public string access_token;
    public string token_type;
    public int expires_in;
    public string refresh_token;

    public Token(string accessToken, string tokenType, int expiresIn, string refreshToken)
    {
        access_token = accessToken;
        token_type = tokenType;
        expires_in = expiresIn;
        refresh_token = refreshToken;
    }
}
