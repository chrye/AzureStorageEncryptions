namespace AzStorageEncryptCustomerProvidedKeys.Models
{
    public class StorContent
    {
        public int BlobId { get; set; }

        public string? CPKey { get; set; }
        public String? BlobText { get; set; }

        public bool UploadSuccessful { get; set; }


    }
}
