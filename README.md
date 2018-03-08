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

