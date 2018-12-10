import java.util.Arrays;

public class BackupKey {
    private BackupCipher cipher;
    private byte[] cipherKey;
    private byte[] hashedGoogleId;

    BackupKey(final byte[] header, final String keyVersion, final byte[] serverSalt, final byte[] googleIdSalt, final byte[] hashedGoogleId, final byte[] encryptionIv, final byte[] cipherKey) {
        super();
        this.cipher = new BackupCipher(header, keyVersion, serverSalt, googleIdSalt, encryptionIv);
        this.hashedGoogleId = hashedGoogleId;
        this.cipherKey = cipherKey;
    }

    public BackupCipher getCipher() {
        return cipher;
    }

    public void setCipher(BackupCipher cipher) {
        this.cipher = cipher;
    }

    public byte[] getCipherKey() {
        return cipherKey;
    }

    public void setCipherKey(byte[] cipherKey) {
        this.cipherKey = cipherKey;
    }

    public byte[] getHashedGoogleId() {
        return hashedGoogleId;
    }

    public void setHashedGoogleId(byte[] hashedGoogleId) {
        this.hashedGoogleId = hashedGoogleId;
    }

    public String toString() {
        return "BackupKey [" + this.cipher.toString() + ", hashedGoogleId=" + Arrays.toString(this.hashedGoogleId) + ", cipherKey=" + Arrays.toString(this.cipherKey) + "]";
    }
}
