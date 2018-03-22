[![Build status](https://ci.appveyor.com/api/projects/status/v05cki0xy9uvlkgk/branch/master?svg=true)](https://ci.appveyor.com/project/jmhardison/example-azurekeyvaulthsm-xmlsigning/branch/master) [![Black Duck Security Risk](https://copilot.blackducksoftware.com/github/repos/jmhardison/Example-AzureKeyVaultHSM-XMLSigning/branches/adding-appveyor/badge-risk.svg)](https://copilot.blackducksoftware.com/github/repos/jmhardison/Example-AzureKeyVaultHSM-XMLSigning/branches/adding-appveyor)

# Example Azure KeyVault HMS Protected Key XML Document Signing

This project is an example, correction... ugly example, of how to sign XML Documents using keys that are stored in Azure KeyVault HSM.
In this model, your private key is non-exportable from Azure KeyVault, and requires you to ship a hash for signing.

## Use
```
Example-AzureKeyVaultHMS Document Signing
=============================================================
-aadclientid : Provide the Azure AD Client ID with access to KeyVault.
-aadclientsecret : Provide the Client Secret for AAD Client ID.
-keyvaulturl : URL of KeyVault, such as https://vaultname.vault.azure.net/ 
-certname : name of stored cert/key in vault.
-xmlfiletosign : path and filename of file to sign.
-xmlfiletosave : path and filename of file to save to.
-validateonlyfile : used to only validate the specified file.
-------------------------------------------------------------
Example: cli-exakvdocsign -aadclientid 123 -aadclientsecret 123= -keyvaulturl https://dog.vault.azure.net/ -certname bob -filetosign filename.xml -xmlfiletosave savetofilename.xml
=============================================================
```

* Validation of existing signed XML.

  `dotnet run --validateonlyfile <signedxmltovalidate>`
  
  `cli-exakvdocsign --validateonlyfile <signedxmltovalidate>`

* Sign XML to new file.

  `dotnet run -aadclientid <clientidhere> -aadclientsecret <clientsecrethere> -keyvaulturl <keyvaulturlhere> -certname <certorkeynamehere> -filetosign <filenametosignhere> -xmlfiletosave <filenametosavetohere>`

  `cli-exakvdocsign -aadclientid <clientidhere> -aadclientsecret <clientsecrethere> -keyvaulturl <keyvaulturlhere> -certname <certorkeynamehere> -filetosign <filenametosignhere> -xmlfiletosave <filenametosavetohere>`


## Build

* `dotnet restore`

* `dotnet build`

* `dotnet publish -c Release --self-contained -r <platformid>`
## Stage Testing

In order to test this application out, your keyvault needs to have some stuff protected with HSM. There are several ways to accomplish this setup, but for simplicity lets talk about creating a self-signed certificate inside the keyvault.
To begin...

* In Azure portal, select your deployed keyvault and then click `Certificates`.
* Click `Generate/Import`.
* Fill in information as needed:
  * Method of creation: `Generate`
  * Certificate Name: `name to call the entry by, this is not your CN for the cert.`
  * Type of CA: `Self-signed certificate`
  * Subject: `CN=examplecertname.docsigning.fun`
  * Validity Period: `12` (or more/less)
  * Content Type: `PKCS #12`
  * Lifetime Action Type: `Automatically renew at a given percentage lifetime.`
  * Advanced Policy Configuration:
    * Extended Key Use: `1.3.6.1.5.5.7.3.1, 1.3.6.1.5.5.7.3.2`
    * X.509 Key Usage Flags: `Digital Signature, Key Encipherment`
    * Reuse Key on Renewal: `no`
    * Exporatable Private Key: `No` (important, if yes you cannot do HSM)
    * Key Type: `RSA-HSM`
    * Key Size: `2048` (or higher)
    * Certificate Type: leave blank
* Click `OK` on Advanced Policy, and then click `Create`.
* Your certificate will show in `in progress` until it is finished issuing and storing in KeyVault. Once complete, you can proceed to collect information and test.

Collecting the following information used in the test.
* `Certificate Name`
  * As defined during creation, but can also be seen in the list of issued certificates in the KeyVault -> Certificates portal.
* `Key Vault URL`
  * In KeyVault details -> Overview, retrieve the `DNS Name` field.
* `Application ID`
  * From within Azure Active Directory in the Azure Portal, under `App Registrations` find your application and select it. `Application ID` field is displayed.
* `Application Secret/Key`
  * From the App Registration for your application in the Azure Portal, click `settings` -> `Keys`, generate a new key and copy the value provided.


This application will require rights in your Azure KeyVault, which is assigned under `Access Policies` on your deployed KeyVault's settings in the Azure Portal. Just add your app registration with the following permissions:

* Key Permissions
  * `Get`
  * `Verify`
  * `Sign`

* Certificate Permissions
  * `Get`