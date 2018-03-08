using System;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using System.Xml;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Reflection;


namespace cli_exakvdocsign
{
    //sourced: https://stackoverflow.com/questions/46440422/how-can-i-convert-the-private-key-stored-in-hsm-to-signedxml-signingkey-in-c-sha/46789582
    public class CustomSignedXml: SignedXml
    {
        public CustomSignedXml(XmlDocument xmlDoc):base(xmlDoc)
        {
            
        }

        internal new void ComputeSignature()
        {
            var customerSigner = new CustomSigner();
            CryptoConfig.AddAlgorithm(typeof(cli_exakvdocsign.RSAPKCS1SHA256SignatureDescription),"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");

            var methodInfo = typeof (SignedXml).GetMethod("BuildDigestedReferences",
                BindingFlags.Instance | BindingFlags.NonPublic);
            methodInfo.Invoke(this, null);
            SignedInfo.SignatureMethod = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
            //See if there is a signature description class defined in the Config file
            SignatureDescription signatureDescription =
                CryptoConfig.CreateFromName(SignedInfo.SignatureMethod) as SignatureDescription;
            if (signatureDescription == null)
                throw new CryptographicException("Cryptography_Xml_SignatureDescriptionNotCreated");

            var hashAlg = signatureDescription.CreateDigest();
            if (hashAlg == null)
                throw new CryptographicException("Cryptography_Xml_CreateHashAlgorithmFailed");
            var methodInfo2 = typeof (SignedXml).GetMethod("GetC14NDigest", BindingFlags.Instance | BindingFlags.NonPublic);
            var hashvalue = (byte[]) methodInfo2.Invoke(this, new object[] {hashAlg});

            m_signature.SignatureValue = customerSigner.Sign(hashvalue);;
        }

        public interface ISignerProvider
        {
            byte[] Sign(byte[] data);
        }
    }



    
}
