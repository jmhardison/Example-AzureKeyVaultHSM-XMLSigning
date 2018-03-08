using System;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using System.Xml;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Reflection;
using Microsoft.Azure.KeyVault;
using Microsoft.Azure.KeyVault.Models;


namespace cli_exakvdocsign
{
    public class CustomSigner: CustomSignedXml.ISignerProvider
    {
        public byte[] Sign(byte[] data)
        {
            return cli_exakvdocsign.Program.keyVault.SignAsync(cli_exakvdocsign.Program.KeyVaultAddress, cli_exakvdocsign.Program.KeyName, cli_exakvdocsign.Program.KeyVersion, Microsoft.Azure.KeyVault.WebKey.JsonWebKeySignatureAlgorithm.RS256, data).Result.Result;
        }
    }
}
