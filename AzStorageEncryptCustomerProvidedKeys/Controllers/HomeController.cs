using AzStorageEncryptCustomerProvidedKeys.Models;
using Azure;
using Azure.Core;
using Azure.Core.Cryptography;
using Azure.Identity;
using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Keys.Cryptography;
using Azure.Storage;
using Azure.Storage.Blobs;
using Azure.Storage.Blobs.Models;
using Azure.Storage.Blobs.Specialized;
using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;


namespace AzStorageEncryptCustomerProvidedKeys.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;
        private StorContent _context;
        private static bool bResult = false;

        string m_keyVersion = "2048";
        //string m_keyVersion = "3072";
        //string m_keyVersion = "4096";

        //====== REPLACE WITH YOUR OWN VALUES HERE ========

        private string m_kek = "";  // name of my KEK - Key Encryption Key


        // Storage Account Information
        private string m_storageConnectionString = "";
        private string m_storageAccountName = "";


        // Your key and key resolver instances, either through KeyVault SDK or an external implementation
        private string m_keyVaultName = ""; // name if my key vault

        // The tenant id/client id and client secret for the App registration
        // We will use this service principal to connect to key vault and storage
        private static string m_tenantId = "";
        private static string m_clientId = "";
        private static string m_clientSecret = "";  //secret value

        //===============================


        public HomeController(ILogger<HomeController> logger)
        {
            _logger = logger;
            _context = new StorContent();
            _logger.Log(LogLevel.Information, "constructor");
        }

        public IActionResult Privacy()
        {
            return View();
        }

        public async Task<IActionResult> UploadClientSideEncrypt1()
        {
            FileStream fs = System.IO.File.Create(@"C:\temp\FileClientSideEncrypt1.txt");

            try
            {
                AddText(fs, DateTime.Now.ToString());
                AddText(fs, "\r\n========================");
                AddText(fs, "this is the file to be uploaded using client side encryption.");
                AddText(fs, "\r\n\r\nthere is a great show - crash landing on you.");
                AddText(fs, "\r\n\r\nif you haven't watched it, you really should try");
                AddText(fs, "\r\n\r\nend of file.\r\n");

                var kvUri = "https://" + m_keyVaultName + ".vault.azure.net";

                TokenCredential token =
                    new ClientSecretCredential(
                        m_tenantId,
                        m_clientId,
                        m_clientSecret);
                KeyClient client = new KeyClient(new Uri(kvUri), token);

                KeyVaultKey rasKey = await client.GetKeyAsync(m_kek + "rsa" + m_keyVersion);

                IKeyEncryptionKey key = new CryptographyClient(rasKey.Id, token);
                IKeyEncryptionKeyResolver keyResolver = new KeyResolver(token);

                ClientSideEncryptionOptions encryptionOptions = new ClientSideEncryptionOptions(ClientSideEncryptionVersion.V1_0)
                {
                    KeyEncryptionKey = key,
                    KeyResolver = keyResolver,
                    // string the storage client will use when calling IKeyEncryptionKey.WrapKey()
                    KeyWrapAlgorithm = "RSA1_5"
                };

                // Set the encryption options on the client options
                BlobClientOptions options = new SpecializedBlobClientOptions() { ClientSideEncryption = encryptionOptions };

                // Get your blob client with client-side encryption enabled.
                // Client-side encryption options are passed from service to container clients, and container to blob clients.
                // Attempting to construct a BlockBlobClient, PageBlobClient, or AppendBlobClient from a BlobContainerClient
                // with client-side encryption options present will throw, as this functionality is only supported with BlobClient.
                BlobClient blob = new BlobServiceClient(m_storageConnectionString, options).GetBlobContainerClient("container-client-side-encrypt").GetBlobClient("upload-clientside-"+ m_keyVersion + "encrypted.txt");

                // Upload the encrypted contents to the blob.
                await blob.UploadAsync(fs);

                TempData["CSE-UploadResult"] = " OK ";
            }
            catch (Exception ex)
            {
                TempData["CSE-UploadResult"] = " Failed    >>>> " + ex.Message;
            }
            finally
            {
                fs.Close();
            }

            return RedirectToAction(nameof(Privacy));

        }

        public async Task<IActionResult> DownloadClientSideEncrypt1()
        {
            try
            {
                // Your key and key resolver instances, either through KeyVault SDK or an external implementation
                var kvUri = "https://" + m_keyVaultName + ".vault.azure.net";

                TokenCredential token =
                    new ClientSecretCredential(
                        m_tenantId,
                        m_clientId,
                        m_clientSecret);
                KeyClient client = new KeyClient(new Uri(kvUri), token);

                KeyVaultKey rasKey = await client.GetKeyAsync(m_kek+"rsa"+ m_keyVersion);

                IKeyEncryptionKey key = new CryptographyClient(rasKey.Id, token);
                IKeyEncryptionKeyResolver keyResolver = new KeyResolver(token);

                ClientSideEncryptionOptions encryptionOptions = new ClientSideEncryptionOptions(ClientSideEncryptionVersion.V1_0)
                {
                    KeyEncryptionKey = key,
                    KeyResolver = keyResolver,
                    // string the storage client will use when calling IKeyEncryptionKey.WrapKey()
                    KeyWrapAlgorithm = "RSA1_5"
                };

                // Set the encryption options on the client options
                BlobClientOptions options = new SpecializedBlobClientOptions() { ClientSideEncryption = encryptionOptions };

                // Get your blob client with client-side encryption enabled.
                // Client-side encryption options are passed from service to container clients, and container to blob clients.
                // Attempting to construct a BlockBlobClient, PageBlobClient, or AppendBlobClient from a BlobContainerClient
                // with client-side encryption options present will throw, as this functionality is only supported with BlobClient.
                BlobClient blob = new BlobServiceClient(m_storageConnectionString, options).GetBlobContainerClient("container-client-side-encrypt").GetBlobClient("upload-clientside-" + m_keyVersion + "encrypted.txt");

                // Download and decrypt the encrypted contents from the blob.
                var outputStream = new MemoryStream();
                blob.DownloadTo(outputStream);

                outputStream.Position = 0;

                string destinationFilePath = @"C:\temp\FileClientSideEncrypt1-download.txt";

                using (FileStream file = new FileStream(destinationFilePath, FileMode.Create, System.IO.FileAccess.Write))
                {
                    outputStream.CopyTo(file);
                    file.Close();
                    outputStream.Close();
                }

                TempData["CSE-DownloadResult1"] = " OK ";
            }
            catch (Exception ex)
            {
                TempData["CSE-DownloadResult1"] = " Failed    >>>> " + ex.Message;
            }

            return RedirectToAction(nameof(Privacy));

        }
    
            



        #region Customer Provided Keys

        public IActionResult Index()
        {
            return View();
        }

        
        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }

        private static void AddText(FileStream fs, string value)
        {
            byte[] info = new UTF8Encoding(true).GetBytes(value);
            fs.Write(info, 0, info.Length);
        }

        // POST: Movies/Create
        // To protect from overposting attacks, please enable the specific properties you want to bind to, for 
        // more details see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> UploadWithCustomerProvidedKey1([Bind("BlobId, CPKey, BlobText")] StorContent storContent)
        {
            _context = new StorContent();

            //if (ModelState.IsValid)
            {
                string randomString = "mycustomerkey";
                SHA256 sha256Hash = SHA256.Create();
                byte[] key = sha256Hash.ComputeHash(Encoding.UTF8.GetBytes(randomString));

                FileStream fs = System.IO.File.Create(@"C:\temp\File1.txt");

                AddText(fs, DateTime.Now.ToString());
                AddText(fs, "\r\n========================");
                AddText(fs, "Hi, there!\r\n");
                AddText(fs, "This is a test file for uploading using Customer Provided Keys.\r\n");
                AddText(fs, "\r\nWe will do several uploads and downloads using different sets of keys");
                AddText(fs, "\r\nto show you how this works.\r\n");
                AddText(fs, "\r\nHope this helps you understand the process.\r\n");

                try
                {
                    // option 1 - 
                    //string blobUriString = "";
                    //Uri blobUri = new Uri(blobUriString);

                    //string keySha256 = "";

                    //await UploadBlobWithClientKey1(blobUri, fs, key, keySha256);


                    // option 3 - user app registration token. Works OK
                    string containerName = "container-mmk-cpk";
                    string blobName = "my-upload-file-3.txt";

                    await UploadBlobWithClientKey3(m_storageAccountName, containerName, blobName, fs, key);

                    //option 2 - use connectionstring. Works OK
                    //blobName = "my-upload-file-2.txt";
                    //await UploadBlobWithClientKey2(accountName, m_storageConnectionString, containerName, blobName, fs, key);

                    bResult = true;
                }
                catch (Exception ex)
                {
                    bResult = false;
                }
                finally { fs.Close(); }
                
            }

            if (bResult)
                TempData["UploadResult"] = " OK ";
            else 
                TempData["UploadResult"] = " Failed ";

            return RedirectToAction(nameof(Index));

        }

        async static Task UploadBlobWithClientKey1(Uri blobUri,
                                          Stream data,
                                          byte[] key,
                                          string keySha256)
        {
            // Create a new customer-provided key.
            // Key must be AES-256.
            var cpk = new CustomerProvidedKey(key);

            // Check the key's encryption hash.
            if (cpk.EncryptionKeyHash != keySha256)
            {
                throw new InvalidOperationException("The encryption key is corrupted.");
            }

            // Specify the customer-provided key on the options for the client.
            BlobClientOptions options = new BlobClientOptions()
            {
                CustomerProvidedKey = cpk
            };

            // Create the client object with options specified.
            BlobClient blobClient = new BlobClient(
                blobUri,
                new DefaultAzureCredential(),
                options);

            // If the container may not exist yet,
            // create a client object for the container.
            // The container client retains the credential and client options.
            BlobContainerClient containerClient =
                blobClient.GetParentBlobContainerClient();

            try
            {
                // Create the container if it does not exist.
                await containerClient.CreateIfNotExistsAsync();

                // Upload the data using the customer-provided key.
                await blobClient.UploadAsync(data);
            }
            catch (RequestFailedException e)
            {
                Console.WriteLine(e.Message);
                Console.ReadLine();
                throw;
            }
        }


        async static Task UploadBlobWithClientKey2(
            string accountName,
            string connectionString,
            string containerName,
            string blobName,
            Stream data,
            byte[] key)
        {
            const string blobServiceEndpointSuffix = ".blob.core.windows.net";
            Uri accountUri = new Uri("https://" + accountName + blobServiceEndpointSuffix);

            // Specify the customer-provided key on the options for the client.
            BlobClientOptions options = new BlobClientOptions()
            {
                CustomerProvidedKey = new CustomerProvidedKey(key)
            };
            // Create a client object for the Blob service, including options.
            BlobServiceClient serviceClient = new BlobServiceClient(connectionString, options);

            // Create a client object for the container.
            // The container client retains the credential and client options.
            BlobContainerClient containerClient = serviceClient.GetBlobContainerClient(containerName);

            // Create a new block blob client object.
            // The blob client retains the credential and client options.
            BlobClient blobClient = containerClient.GetBlobClient(blobName);

            try
            {
                // Create the container if it does not exist.
                await containerClient.CreateIfNotExistsAsync();

                // Upload the data using the customer-provided key.
                data.Position = 0;
                await blobClient.UploadAsync(data);
            }
            catch (RequestFailedException e)
            {
                Console.WriteLine(e.Message);
                Console.ReadLine();
                throw;
            }
        }

        async static Task UploadBlobWithClientKey3(
                    string accountName,
                    string containerName,
                    string blobName,
                    Stream data,
                    byte[] key)
        {
            const string blobServiceEndpointSuffix = ".blob.core.windows.net";
            Uri accountUri = new Uri("https://" + accountName + blobServiceEndpointSuffix);

            // Specify the customer-provided key on the options for the client.
            BlobClientOptions options = new BlobClientOptions()
            {
                CustomerProvidedKey = new CustomerProvidedKey(key)
            };

            // Create App registration:
            // Tenant: Microsoft Directory
            // Name: appRegAccessStorage
            TokenCredential token =
                new ClientSecretCredential(
                    m_tenantId,
                    m_clientId,
                    m_clientSecret);
            // Create a client object for the Blob service, including options.
            BlobServiceClient serviceClient = new BlobServiceClient(accountUri,
                token, options);

            // Create a client object for the container.
            // The container client retains the credential and client options.
            BlobContainerClient containerClient = serviceClient.GetBlobContainerClient(containerName);

            // Create a new block blob client object.
            // The blob client retains the credential and client options.
            BlobClient blobClient = containerClient.GetBlobClient(blobName);

            try
            {
                // Create the container if it does not exist.
                await containerClient.CreateIfNotExistsAsync();

                // Upload the data using the customer-provided key.
                data.Position = 0;
                await blobClient.UploadAsync(data);
                data.Flush();
                data.Close();
            }
            catch (RequestFailedException e)
            {
                Console.WriteLine(e.Message);
                Debug.WriteLine(e.Message);
                Console.ReadLine();
                throw;
            }
        }


        public async Task<IActionResult> DownloadWithCustomerProvidedKey1()
        {
            string randomString = "mycustomerkey";
            SHA256 sha256Hash = SHA256.Create();
            byte[] key = sha256Hash.ComputeHash(Encoding.UTF8.GetBytes(randomString));

            string downloadFilePath = @"C:\temp\File1-download.txt";


            string containerName = "container-mmk-cpk";
            string blobName = "my-upload-file-3.txt";

            await DownloadBlobWithClientKey(m_storageAccountName, containerName, blobName, downloadFilePath, key);


            _context.UploadSuccessful = true;

            if (_context.UploadSuccessful)
                TempData["DownloadResult1"] = " OK ";
            else 
                TempData["DownloadResult1"] = " Failed ";

            return RedirectToAction(nameof(Index));

        }

        async static Task DownloadBlobWithClientKey(
                   string accountName,
                   string containerName,
                   string blobName,
                   string destinationFilePath,
                   byte[] key)
        {
            const string blobServiceEndpointSuffix = ".blob.core.windows.net";
            Uri accountUri = new Uri("https://" + accountName + blobServiceEndpointSuffix);

            // Specify the customer-provided key on the options for the client.
            BlobClientOptions options = new BlobClientOptions()
            {
                CustomerProvidedKey = new CustomerProvidedKey(key)
            };

            TokenCredential token =
                new ClientSecretCredential(
                    m_tenantId,
                    m_clientId,
                    m_clientSecret);
            // Create a client object for the Blob service, including options.
            BlobServiceClient serviceClient = new BlobServiceClient(accountUri,
                token, options);

            // Create a client object for the container.
            // The container client retains the credential and client options.
            BlobContainerClient containerClient = serviceClient.GetBlobContainerClient(containerName);

            // Create a new block blob client object.
            // The blob client retains the credential and client options.
            BlobClient blobClient = containerClient.GetBlobClient(blobName);

            try
            {
                var memoryStream = new MemoryStream();
                await blobClient.DownloadToAsync(memoryStream);

                memoryStream.Position = 0;

                using (FileStream file = new FileStream(destinationFilePath, FileMode.Create, System.IO.FileAccess.Write))
                {
                    memoryStream.CopyTo(file);
                    file.Close();
                    memoryStream.Close();
                }
                


            }
            catch (RequestFailedException e)
            {
                Console.WriteLine(e.Message);
                
                throw e;
            }
        }

        public async Task<IActionResult> DownloadWithCustomerProvidedKey2()
        {
            string randomString = "mycustomerkey-diff";
            SHA256 sha256Hash = SHA256.Create();
            byte[] key = sha256Hash.ComputeHash(Encoding.UTF8.GetBytes(randomString));

            string downloadFilePath = @"C:\temp\File1-download3.txt";

            string containerName = "container-mmk-cpk";
            string blobName = "my-upload-file-3.txt";

            try
            {
                await DownloadBlobWithClientKey(m_storageAccountName, containerName, blobName, downloadFilePath, key);
                TempData["DownloadResult2"] = " OK ";
            }
            catch (RequestFailedException e)
            {
                TempData["DownloadResult2"] = " Failed            >>>   " + e.Message;
            }



            return RedirectToAction(nameof(Index));

        }

        #endregion
    }
}