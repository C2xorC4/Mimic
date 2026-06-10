package deception

// Size/shape limits for config-driven content (honeypot scale; everything is
// held in memory).
const (
	maxSeedFileSize = 1 << 20 // 1 MiB cap on a single seeded file
	maxGenChildren  = 1000    // clamp on generated/maze children per directory
)

// --- default bait artifacts (moved from the smb VFS) ---

var baitPasswords = []byte(`# Network Credentials - CONFIDENTIAL
# Last updated: 2024-09-14

[Database]
host=10.0.1.50
user=sa
password=Adm1n@SQL2019!

[Backup Service]
host=10.0.1.20
user=backup_svc
password=Backup$ecure99

[vCenter]
host=10.0.1.10
user=administrator@vsphere.local
password=VMware1!

[Firewall]
host=10.0.1.1
user=admin
password=F!rewall2024
`)

var baitBackupCreds = []byte(`Veeam Backup Service Account
Domain: CORP
Username: svc_backup
Password: V33m@Backup!23

SQL Backup Job
Server: SQL-PROD-01
User: sa
Pass: Adm1n@SQL2019!
`)

// baitSSHKey is a plausible-looking (but fake) RSA private key.
var baitSSHKey = []byte(
	"-----BEGIN RSA PRIVATE KEY-----\n" +
		"MIIEpAIBAAKCAQEA2a2rwplBQLzamygykEMmYz0+Kcj3bKBp29P2rFj7qQROep\n" +
		"q1pnMxzBNV5dEomD8V8bJZ9gQEoMqrLHNYKjb2MQZG1SLAe0+qkVxMRZ5CgTM\n" +
		"lrX9QVuWPMpCuuB9hNAXM5G5p3N7HJMT8s6I5bDRJqIyFLRBdAT0iOKgMJEhV\n" +
		"K9GXMV2LQJM9hKEf4q8lZnlRN+0pNDhkHdJzOFG8MZ9aLePYVmEBSgOFiMN5b\n" +
		"PX5MQQr8G4V9RjFqI7BmHwD+mVkSbPfFXvXyLX8q5VVfRQ5O2J6Lw8h3AqtWx\n" +
		"V+Z5kZlK3XDYF+z5PGT7Bq3X9W0j8I0RvRwIDAQABAoIBAC5RgZ+hBx7xHNaM\n" +
		"-----END RSA PRIVATE KEY-----\n",
)
