package qa.infosec.testng.netsign.upki;

import cn.com.infosec.netsign.agent.UpkiAgent;
import cn.com.infosec.netsign.agent.UpkiResult;
import org.testng.Assert;
import org.testng.Reporter;
import org.testng.annotations.Test;
import qa.infosec.testng.netsign.dataprovider.NetSignDataProvider;
import qa.infosec.testng.netsign.dataprovider.util.ParameterUtil;
import qa.infosec.testng.netsign.dataprovider.util.ParseFile;
import qa.infosec.testng.netsign.dataprovider.util.SFTPFile;
import qa.infosec.testng.netsign.dataprovider.util.Utils;
import qa.infosec.testng.netsign.init.NetSignServerInit;

import java.util.Map;

/**
 * @author zhaoyongzhi
 * @ClassName: TestEncryptEnvelope
 * @date 2020-03-02 18:05
 * @Description: ���������ŷ�
 * <p>�������ǵ㣺</p>
 * <p>1�����������ŷ⣬֤��DN��֤��Base64��Ϣƥ�䣬�Գ��㷨ΪDES/3DES/RC2/RC4/SM4/AES</p>
 * <p>2�����������ŷ⣬֤��DN��֤��Base64��Ϣƥ�䣬�Գ��㷨Ϊdes/3des/rc2/rc4/sm4/aes</p>
 * <p>3�����������ŷ⣬��ʹ��DN</p>
 * <p>4�����������ŷ⣬��ʹ��SN</p>
 * <p>5�����������ŷ⣬��ʹ��bankcode</p>
 * <p>6�����������ŷ⣬DN/SN/bankcodeΪ��</p>
 * <p>7�����������ŷ⣬DN/SN/bankcodeΪnull</p>
 * <p>8�����������ŷ⣬DN/SN/bankcode��Base64��Ϣ��Ϊ�ջ�null</p>
 * <p>9�����������ŷ⣬�Գ��㷨Ϊ�ջ�null</p>
 */
@Test(groups = "abcjew.encryptenvelope")
public class TestEncryptEnvelope {
    static String ip, port, password;
    static String host, sftp_port, sftp_password, sftp_user;

    NetSignServerInit init = new NetSignServerInit();
    UpkiAgent agent;
    SFTPFile tmp = new SFTPFile();

    {
        Map<String, String> map = ParseFile.parseProperties(null);
        ip = map.get("ServerIP");
        port = map.get("ServerPortPBC2G");
        password = map.get("APIPassword");

        host = map.get("sftp_ip");
        sftp_port = map.get("sftp_port");
        sftp_user = map.get("sftp_user");
        sftp_password = map.get("sftp_password");

        agent = init.upkiStart(ip, port, password, true, 20);
        tmp.downFile(sftp_user, host, sftp_port, sftp_password, ParameterUtil.sftpdetailpath, ParameterUtil.localdetailpath);
    }

    /**
     * ���������ŷ⣬֤��DN��Base64��Ϣƥ��
     *
     * @param sAlg �Գ��㷨ΪDES/3DES/RC2/RC4/SM4/AES
     */
    @Test(groups = "abcjew.encryptenvelope.normal", dataProvider = "symmalg-allcert-dn", dataProviderClass =
            NetSignDataProvider.class)
    public void testEncryptEnvelope_01(String sAlg, String str) {
        System.out.println("Test ABCJEW EncryptEnvelope Cert DN Normal");
        String[] split = str.split("%");
        String sCertDN = split[0];
        String sPublicKey = split[1];
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        if ("DESEde".equals(sAlg)) {
            sAlg = "3DES";
        }
        try {
            upkiResult = agent.encryptEnvelope(pOrgData, sCertDN, sAlg, sPublicKey);
            if (upkiResult.getResults() == null || upkiResult.getReturnCode() != 0) {
                Assert.fail("���������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + e.getMessage());
        }
    }

    /**
     * ���������ŷ⣬֤��DN��Base64��Ϣƥ��
     *
     * @param sAlg �Գ��㷨Ϊdes/3des/rc2/rc4/sm4/aes
     * @param str
     */
    @Test(groups = "abcjew.encryptenvelope.normal", dataProvider = "symmalg-allcert-dn", dataProviderClass =
            NetSignDataProvider.class)
    public void testEncryptEnvelope_02(String sAlg, String str) {
        System.out.println("Test ABCJEW EncryptEnvelope Cert DN Normal");
        String[] split = str.split("%");
        String sCertDN = split[0];
        String sPublicKey = split[1];
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        if ("DESEde".equals(sAlg)) {
            sAlg = "3DES";
        }
        try {
            upkiResult = agent.encryptEnvelope(pOrgData, sCertDN, sAlg.toLowerCase(), sPublicKey);
            if (upkiResult.getReturnCode() != -100112) {
                Assert.fail("���������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
            Reporter.log("���������ŷ⣨EncryptEnvelope�����ԳƼ����㷨��֧��Сд����");
        } catch (Exception e) {
            Assert.fail("���������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + e.getMessage());
        }
    }

    /**
     * ���������ŷ⣬��ʹ��DN
     *
     * @param sAlg �Գ��㷨ΪDES/3DES/RC2/RC4/SM4/AES
     * @param str
     */
    @Test(groups = "abcjew.encryptenvelope.normal", dataProvider = "symmalg-allcert-dn", dataProviderClass =
            NetSignDataProvider.class)
    public void testEncryptEnvelope_03(String sAlg, String str) {
        System.out.println("Test ABCJEW EncryptEnvelope  DN Normal");
        String[] split = str.split("%");
        String sCertDN = split[0];
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        if ("DESEde".equals(sAlg)) {
            sAlg = "3DES";
        }
        try {
            upkiResult = agent.encryptEnvelope(pOrgData, sCertDN, sAlg, null);
            if (upkiResult.getResults() == null || upkiResult.getReturnCode() != 0) {
                Assert.fail("���������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + e.getMessage());
        }
    }

    /**
     * ���������ŷ⣬��ʹ��SN
     *
     * @param sAlg �Գ��㷨ΪDES/3DES/RC2/RC4/SM4/AES
     * @param str
     */
    @Test(groups = "abcjew.encryptenvelope.normal", dataProvider = "symmalg-allcert-sn", dataProviderClass =
            NetSignDataProvider.class)
    public void testEncryptEnvelope_04(String sAlg, String str) {
        System.out.println("Test ABCJEW EncryptEnvelope  SN Normal");
        String[] split = str.split("%");
        String sCertSN = split[0];
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        if ("DESEde".equals(sAlg)) {
            sAlg = "3DES";
        }
        try {
            upkiResult = agent.encryptEnvelope(pOrgData, sCertSN, sAlg, null);
            if (upkiResult.getResults() == null || upkiResult.getReturnCode() != 0) {
                Assert.fail("���������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + e.getMessage());
        }
    }

    /**
     * ���������ŷ⣬��ʹ��bankcode
     *
     * @param sAlg �Գ��㷨ΪDES/3DES/RC2/RC4/SM4/AES
     */
    @Test(groups = "abcjew.encryptenvelope.normal", dataProvider = "all-symmalg-bankcode", dataProviderClass =
            NetSignDataProvider.class)
    public void testEncryptEnvelope_05(String sAlg, String bankcode) {
        System.out.println("Test ABCJEW EncryptEnvelope  BankCode Normal");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        if ("DESEde".equals(sAlg)) {
            sAlg = "3DES";
        }
        try {
            upkiResult = agent.encryptEnvelope(pOrgData, bankcode, sAlg, null);
            if (upkiResult.getReturnCode() != 0) {
                if (upkiResult.getReturnCode() != -100203) {
                    Assert.fail("���������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
                }
                Reporter.log("���������ŷ⣨encryptEnvelope��:����֤���bankcode��ҵ��ʧ��");
            }
        } catch (Exception e) {
            Assert.fail("���������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + e.getMessage());
        }
    }

    /**
     * ���������ŷ⣬DN/SN/bankcodeΪ��
     *
     * @param sAlg �Գ��㷨ΪDES/3DES/RC2/RC4/SM4/AES
     * @param str
     */
    @Test(groups = "abcjew.encryptenvelope.normal", dataProvider = "symmalg-allcert-dn", dataProviderClass =
            NetSignDataProvider.class)
    public void testEncryptEnvelope_06(String sAlg, String str) {
        System.out.println("Test ABCJEW EncryptEnvelope Cert DN/SN/BankCode Empty");
        String[] split = str.split("%");
        String sPublicKey = split[1];
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        if ("DESEde".equals(sAlg)) {
            sAlg = "3DES";
        }
        try {
            upkiResult = agent.encryptEnvelope(pOrgData, "", sAlg, sPublicKey);
            if (upkiResult.getResults() == null || upkiResult.getReturnCode() != 0) {
                Assert.fail("���������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + e.getMessage());
        }
    }

    /**
     * ���������ŷ⣬DN/SN/bankcodeΪnull
     *
     * @param sAlg �Գ��㷨ΪDES/3DES/RC2/RC4/SM4/AES
     * @param str
     */
    @Test(groups = "abcjew.encryptenvelope.normal", dataProvider = "symmalg-allcert-dn", dataProviderClass =
            NetSignDataProvider.class)
    public void testEncryptEnvelope_07(String sAlg, String str) {
        System.out.println("Test ABCJEW EncryptEnvelope Cert DN/SN/BankCode Null");
        String[] split = str.split("%");
        String sPublicKey = split[1];
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        if ("DESEde".equals(sAlg)) {
            sAlg = "3DES";
        }
        try {
            upkiResult = agent.encryptEnvelope(pOrgData, null, sAlg, sPublicKey);
            if (upkiResult.getResults() == null || upkiResult.getReturnCode() != 0) {
                Assert.fail("���������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + e.getMessage());
        }
    }

    /**
     * ���������ŷ⣬DN/SN/bankcodeΪnull
     *
     * @param str
     */
    @Test(groups = "abcjew.encryptenvelope.normal", dataProvider = "emptys-parameter", dataProviderClass =
            NetSignDataProvider.class)
    public void testEncryptEnvelope_08(String str) {
        System.out.println("Test ABCJEW EncryptEnvelope Cert DN/SN/BankCode Null or Empty");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        String sAlg = "AES";
        try {
            upkiResult = agent.encryptEnvelope(pOrgData, str, sAlg, str);
            if (upkiResult.getReturnCode() != -100203) {
                if (upkiResult.getReturnCode() != 0) {
                    Assert.fail("���������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
                }
                Reporter.log("���������ŷ⣨encryptEnvelope��:Base64֤����Ϣ����Ϊ���ַ��������������ŷ�ɹ�");
            }
        } catch (Exception e) {
            Assert.fail("���������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + e.getMessage());
        }
    }

    /**
     * �Գ��㷨Ϊ�ջ�null
     *
     * @param sAlg
     */
    @Test(groups = "abcjew.encryptenvelope.normal", dataProvider = "emptys-parameter", dataProviderClass =
            NetSignDataProvider.class)
    public void testEncryptEnvelope_09(String sAlg) {
        System.out.println("Test ABCJEW EncryptEnvelope sAlg Null or Empty");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        String sCertDN = "CN=c020crlfbdIssueModeHTTP";
        try {
            upkiResult = agent.encryptEnvelope(pOrgData, sCertDN, sAlg, null);
            if (upkiResult.getReturnCode() != -100203) {
                if (upkiResult.getReturnCode() != 0) {
                    Assert.fail("���������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
                }
                Reporter.log("���������ŷ⣨encryptEnvelope��:�Գ��㷨Ϊ�ջ�null�����������ŷ�ɹ�");
            }
        } catch (Exception e) {
            Assert.fail("���������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + e.getMessage());
        }
    }
}
