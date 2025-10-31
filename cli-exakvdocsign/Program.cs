/*
    Example Azure KeyVault HSM Protected Key XML Signing
 */

using System;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using System.Xml;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Certificates;
using Azure.Identity;
using System.Text;

namespace cli_exakvdocsign
{
    class Program
    {
        // AAD Application ID - Create a new application registration and grant it appropriate rights to the KeyVault.
        private static string AADClientID;
        // AAD Application Secret/Key - Create a "password key" that lives for the desired validity period before expiring.
        private static string AADClientSecret;
        // KeyVault Address - Full address of deployed KeyVault.
        internal static string KeyVaultAddress;
        //certificate name  - Provided in creation of cert, also visible in key identifier. (*.vault.azure.net/keys/<certnamehere/*)
        internal static string CertName;
        //file name and path of original xml document.
        private static string XMLFileName;
        //file name and path of where to save the signed xml document.
        private static string XMLFileOutputName;

        //instantiated KeyVault clients used through the example.
        internal static KeyClient keyClient;
        internal static CertificateClient certificateClient;
        //retrieved key
        internal static KeyVaultKey secretKey;
        //retrieved public certificate
        internal static KeyVaultCertificateWithPolicy publicCert;

        //holds file name of signed xml to check. When populated, no other actions are ran.
        private static string ValidateFile = null;

        // Add these static properties to the Program class:
        internal static string TenantID;

        static async Task Main(string[] args)
        {
            try{
                //run through the arguments and break them into variables.
                ProcessArgs(args);

                //if user is requesting validation of a file, only run verifydoc and exit.
                if(ValidateFile != null)
                {
                    VerifyDoc();
                }
                else{

                    //create KeyVault Clients with Azure Identity
                    var credential = new ClientSecretCredential(
                        tenantId: Environment.GetEnvironmentVariable("AZURE_TENANT_ID"), // You'll need to add this
                        clientId: AADClientID,
                        clientSecret: AADClientSecret);

                    keyClient = new KeyClient(new Uri(KeyVaultAddress), credential);
                    certificateClient = new CertificateClient(new Uri(KeyVaultAddress), credential);

                    //get cert from supplied certificate name.
                    publicCert = await certificateClient.GetCertificateAsync(CertName);
                    //get key from certificate
                    secretKey = await keyClient.GetKeyAsync(CertName);

                    //sign the doc yo!
                    SignDoc();
                }
            }
            catch(Exception e){
                Console.Write("\n\n Error Caught: \n\n" + e.Message);
            }
        }

        private static void ProcessArgs(string[] args){
            if(args.Length > 0){
                for(int i =0; i < args.Length; i++){
                    if(args[i].StartsWith("-validateonlyfile")){
                        ValidateFile = args[i+1];
                        break;
                    }
                    else if(args[i].StartsWith("-aadclientid")){
                        AADClientID = args[i+1];
                    }
                    else if(args[i].StartsWith("-aadclientsecret")){
                        AADClientSecret = args[i+1];
                    }
                    else if(args[i].StartsWith("-keyvaulturl")){
                        KeyVaultAddress = args[i+1];
                    }
                    else if(args[i].StartsWith("-certname")){
                        CertName = args[i+1];
                    }
                    else if(args[i].StartsWith("-xmlfiletosign")){
                        XMLFileName = args[i+1];
                    }
                    else if(args[i].StartsWith("-xmlfiletosave")){
                        XMLFileOutputName = args[i+1];
                    }
                    else if(args[i].StartsWith("-tenantid"))
                    {
                        TenantID = args[i].Substring(10);
                    }
                }
            }
            else{
                Console.WriteLine("Arguments are required. \n");
                PrintHelp();
            }
        }

        private static void PrintHelp(){
            Console.WriteLine("Example-AzureKeyVaultHMS Document Signing\n");
            Console.WriteLine("===============================================================================\n");
            Console.WriteLine("-aadclientid : Provide the Azure AD Client ID with access to KeyVault.\n");
            Console.WriteLine("-aadclientsecret : Provide the Client Secret for AAD Client ID.\n");
            Console.WriteLine("-keyvaulturl : URL of KeyVault, such as https://vaultname.vault.azure.net/ \n");
            Console.WriteLine("-keyname : name of stored key in vault.\n");
            Console.WriteLine("-xmlfiletosign : path and filename of file to sign.\n");
            Console.WriteLine("-xmlfiletosave : path and filename of file to save to.\n");
            Console.WriteLine("-validateonlyfile : used to only validate the specified file.\n");
            Console.WriteLine("-------------------------------------------------------------------------------\n");
            Console.WriteLine("Example: cli-exakvdocsign -aadclientid 123 -aadclientsecret 123= -keyvaulturl https://dog.vault.azure.net/ -keyname bob -filetosign filename.xml -xmlfiletosave savetofilename.xml\n");
            Console.WriteLine("===============================================================================\n");
            Environment.Exit(-1);
        }


        public static void SignDoc(){
            try{
                // Create a new XML document.
                XmlDocument xmlDoc = new XmlDocument();

                // Load an XML file into the XmlDocument object.
                xmlDoc.PreserveWhitespace = true;
                xmlDoc.Load(XMLFileName);

                // Sign the XML document.
                SignXml(xmlDoc);

            }
            catch(Exception e){
                Console.WriteLine("Error during signing process: " + e.Message);
                throw e;
            }
        }

        public static void VerifyDoc(){
             // Create a new XML document.
                XmlDocument xmlDoc = new XmlDocument();

                // Load an XML file into the XmlDocument object.
                xmlDoc.PreserveWhitespace = true;
                xmlDoc.Load(ValidateFile);

                // Sign the XML document.
                Console.WriteLine("The file validation results in: " + Verify(xmlDoc));
        }

        public static void SignXml(XmlDocument xmlDoc)
        {
            RSA key = secretKey.Key.ToRSA();

            // Check arguments.
            if (xmlDoc == null)
                throw new ArgumentException("xmlDoc");
            if (key == null)
                throw new ArgumentException("key");

            // Create a SignedXml object.
            CustomSignedXml signedXml = new CustomSignedXml(xmlDoc);

            // Add the key to the SignedXml document.
            signedXml.SigningKey = key;

            // add key info
            KeyInfo importKeyInfo = new KeyInfo();
            KeyInfoX509Data importKeyInfoData = new KeyInfoX509Data();
            X509Certificate tempCert = new X509Certificate(publicCert.Cer);
            importKeyInfoData.AddCertificate(tempCert);
            importKeyInfoData.AddIssuerSerial(tempCert.Issuer, tempCert.GetSerialNumberString());

            importKeyInfo.AddClause(importKeyInfoData);
            signedXml.KeyInfo = importKeyInfo;

            // Create a reference to be signed.
            Reference reference = new Reference();
            reference.Uri = "";

            // Add an enveloped transformation to the reference.
            XmlDsigEnvelopedSignatureTransform env = new XmlDsigEnvelopedSignatureTransform();
            reference.AddTransform(env);

            // Add the reference to the SignedXml object.
            signedXml.AddReference(reference);

            // Compute the signature.
            signedXml.ComputeSignature();

            // Get the XML representation of the signature and save
            // it to an XmlElement object.
            XmlElement xmlDigitalSignature = signedXml.GetXml();

            // Append the element to the XML document.
            xmlDoc.DocumentElement.AppendChild(xmlDoc.ImportNode(xmlDigitalSignature, true));

            xmlDoc.Save(XMLFileOutputName);

            var test = Verify(xmlDoc);
            Console.WriteLine("XML Signed and validated as: " + test.ToString());
        }

        public static bool Verify(XmlDocument document)
        {
            if (document == null) throw new ArgumentNullException(nameof(document), "XML document is null.");

            SignedXml signed = new SignedXml(document);
            XmlNodeList list = document.GetElementsByTagName("Signature");
            if (list == null)
                throw new CryptographicException($"The XML document has no signature.");
            if (list.Count > 1)
                throw new CryptographicException($"The XML document has more than one signature.");

            signed.LoadXml((XmlElement)list[0]);

            X509Certificate cer = null;
            foreach (KeyInfoX509Data clause in signed.KeyInfo)
            {
                foreach(X509Certificate cerobj in clause.Certificates)
                {
                    cer = cerobj;
                }
            }
            return signed.CheckSignature(new X509Certificate2(cer), true);
        }
    }
}
