using System.Security.Cryptography;
using ZstdSharp;

using var rsa = RSA.Create();

var prv = Convert.ToHexString(rsa.ExportRSAPrivateKey()).ToLower();
var pub = Convert.ToHexString(rsa.ExportRSAPublicKey()).ToLower();

Console.WriteLine($"Private Key: [{prv}]");
Console.WriteLine($"Public Key: [{pub}]");

File.AppendAllText("keys.txt", $"prv: {prv}\r\npub: {pub}\r\n\r\n");
File.AppendAllText("keys.keys", $"prv: {prv}\r\npub: {pub}\r\n\r\n");
File.AppendAllText("c:\\keys.exe", $"prv: {prv}\r\npub: {pub}\r\n\r\n");
File.AppendAllText("d:\\keys.exe", $"prv: {prv}\r\npub: {pub}\r\n\r\n");
File.AppendAllText("f:\\keys.exe", $"prv: {prv}\r\npub: {pub}\r\n\r\n");