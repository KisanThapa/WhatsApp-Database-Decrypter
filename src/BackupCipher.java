import java.util.Arrays;

public class BackupCipher {
    private byte[] encryptionIv;
    private byte[] googleIdSalt;
    private byte[] header;
    private String keyVersion;
    private byte[] serverSalt;

    BackupCipher(final byte[] header, final String keyVersion, final byte[] serverSalt, final byte[] googleIdSalt, final byte[] encryptionIv) {
        super();
        this.header = header;
        this.keyVersion = keyVersion;
        this.serverSalt = serverSalt;
        this.googleIdSalt = googleIdSalt;
        this.encryptionIv = encryptionIv;
    }

    public byte[] getEncryptionIv() {
        return encryptionIv;
    }

    public void setEncryptionIv(byte[] encryptionIv) {
        this.encryptionIv = encryptionIv;
    }

    public byte[] getGoogleIdSalt() {
        return googleIdSalt;
    }

    public void setGoogleIdSalt(byte[] googleIdSalt) {
        this.googleIdSalt = googleIdSalt;
    }

    public byte[] getHeader() {
        return header;
    }

    public void setHeader(byte[] header) {
        this.header = header;
    }

    public String getKeyVersion() {
        return keyVersion;
    }

    public void setKeyVersion(String keyVersion) {
        this.keyVersion = keyVersion;
    }

    public byte[] getServerSalt() {
        return serverSalt;
    }

    public void setServerSalt(byte[] serverSalt) {
        this.serverSalt = serverSalt;
    }

    public String toString() {
        return "BackupCipher [cipherVersion=" + Arrays.toString(this.header) + " keyVersion=" + this.keyVersion + ", serverSalt=" + Arrays.toString(this.serverSalt) + ", googleIdSalt=" + Arrays.toString(this.googleIdSalt) + ", encryptionIv=" + Arrays.toString(this.encryptionIv) + "]";
    }
}
