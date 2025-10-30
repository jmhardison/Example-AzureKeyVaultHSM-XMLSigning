using System;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using System.Xml;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Reflection;
using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Keys.Cryptography;

namespace cli_exakvdocsign
{
    public class CustomSigner: CustomSignedXml.ISignerProvider
    {
        public byte[] Sign(byte[] data)
        {
            // Create cryptography client for the key
            var cryptographyClient = new CryptographyClient(cli_exakvdocsign.Program.secretKey.Id, new Azure.Identity.ClientSecretCredential(
                tenantId: Environment.GetEnvironmentVariable("AZURE_TENANT_ID"),
                clientId: Environment.GetEnvironmentVariable("AZURE_CLIENT_ID"), // You'll need to expose this from Program
                clientSecret: Environment.GetEnvironmentVariable("AZURE_CLIENT_SECRET"))); // You'll need to expose this from Program

            // Sign the data using RS256 algorithm
            var signResult = cryptographyClient.SignAsync(SignatureAlgorithm.RS256, data).Result;
            return signResult.Signature;
        }
    }
}
