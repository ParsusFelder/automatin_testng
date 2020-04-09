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
 * @ClassName: TestDecryptEnvelope
 * @date 2020-03-02 18:05
 * @Description: ���������ŷ�
 * <p>�������ǵ㣺</p>
 * <p>1�����������ŷ⣨decryptEnvelope��������ʹ��֤��DN</p>
 * <p>2�����������ŷ⣨decryptEnvelope��������ʹ��֤��SN</p>
 * <p>3�����������ŷ⣨decryptEnvelope��������ʹ��֤��bankcode</p>
 * <p>4�����������ŷ⣨decryptEnvelope��������Ϊnull����ַ�</p>
 * <p>5�����������ŷ⣨decryptEnvelope����DN/SN/BankCodeΪnull</p>
 * <p>6�����������ŷ⣨decryptEnvelope����DN/SN/BankCodeΪ���ַ�</p>
 * <p>7�����������ŷ⣨decryptEnvelope����DN�����ʹ��֤�鲻ƥ��</p>
 * <p>8�����������ŷ⣨decryptEnvelope�������Ĵ۸�</p>
 */
@Test(groups = "abcjew.decryptenvelope")
public class TestDecryptEnvelope {
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
        tmp.downFile(sftp_user, host, sftp_port, sftp_password, ParameterUtil.sftpdetailpath,
                ParameterUtil.localdetailpath);
    }

    /**
     * ���������ŷ⣬����ʹ��֤��DN
     */
    @Test(groups = "abcjew.decryptenvelope.normal", dataProvider = "symmalg-allcert-dn", dataProviderClass =
            NetSignDataProvider.class)
    public void testDecryptEnvelope_01(String sAlg, String str) {
        System.out.println("���������ŷ⣨decryptEnvelope��������ʹ��֤��DN");

        String[] split = str.split("%");
        String sCertDN = split[0];
        String sPublicKey = split[1];
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        String enc_text = null;
        if ("DESEde".equals(sAlg)) {
            sAlg = "3DES";
        }
        // ���������ŷ�
        try {
            upkiResult = agent.encryptEnvelope(pOrgData, sCertDN, sAlg, sPublicKey);
            enc_text = upkiResult.getResults().get(UpkiResult.ENC_TEXT).toString();
            if (upkiResult.getResults() == null || upkiResult.getReturnCode() != 0) {
                Assert.fail("���������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + e.getMessage());
        }
        // ���������ŷ�
        try {
            if (enc_text != null && !enc_text.isEmpty()) {
                upkiResult1 = agent.decryptEnvelope(enc_text, sCertDN);
                if (upkiResult1.getResults() == null || upkiResult1.getReturnCode() != 0) {
                    Assert.fail("���������ŷ�ʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
            }
        } catch (Exception e) {
            Assert.fail("���������ŷ�ʧ�ܣ�" + upkiResult1.getReturnCode() + e.getMessage());
        }
    }

    /**
     * ���������ŷ⣬����ʹ��֤��SN
     */
    @Test(groups = "abcjew.decryptenvelope.normal", dataProvider = "symmalg-allcert-sn", dataProviderClass =
            NetSignDataProvider.class)
    public void testDecryptEnvelope_02(String sAlg, String str) {
        System.out.println("���������ŷ⣨decryptEnvelope��������ʹ��֤��SN");

        String[] split = str.split("%");
        String sCertSN = split[0];
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        String enc_text = null;
        if ("DESEde".equals(sAlg)) {
            sAlg = "3DES";
        }
        // ���������ŷ�
        try {
            upkiResult = agent.encryptEnvelope(pOrgData, sCertSN, sAlg, null);
            enc_text = upkiResult.getResults().get(UpkiResult.ENC_TEXT).toString();
            if (upkiResult.getResults() == null || upkiResult.getReturnCode() != 0) {
                Assert.fail("���������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + e.getMessage());
        }
        // ���������ŷ�
        try {
            if (enc_text != null && !enc_text.isEmpty()) {
                upkiResult1 = agent.decryptEnvelope(enc_text, sCertSN);
                if (upkiResult1.getResults() == null || upkiResult1.getReturnCode() != 0) {
                    Assert.fail("���������ŷ�ʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
            }
        } catch (Exception e) {
            Assert.fail("���������ŷ�ʧ�ܣ�" + upkiResult1.getReturnCode() + e.getMessage());
        }
    }

    /**
     * ���������ŷ⣬����ʹ��֤��bankcode
     */
    @Test(groups = "abcjew.decryptenvelope.normal", dataProvider = "all-symmalg-bankcode", dataProviderClass =
            NetSignDataProvider.class)
    public void testDecryptEnvelope_03(String sAlg, String bankcode) {
        System.out.println("���������ŷ⣨decryptEnvelope��������ʹ��֤��bankcode");

        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        String enc_text = null;
        if ("DESEde".equals(sAlg)) {
            sAlg = "3DES";
        }
        // ���������ŷ�
        try {
            upkiResult = agent.encryptEnvelope(pOrgData, bankcode, sAlg, null);
            if (upkiResult.getReturnCode() != 0) {
                if (upkiResult.getReturnCode() != -100203) {
                    Assert.fail("���������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
                }
                Reporter.log("���������ŷ⣨encryptEnvelope��:����֤���bankcode��ҵ��ʧ��");
                return;
            }
        } catch (Exception e) {
            Assert.fail("���������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + e.getMessage());
        }
        // ���������ŷ�
        if (upkiResult.getResults() != null) {
            enc_text = upkiResult.getResults().get(UpkiResult.ENC_TEXT).toString();
            try {
                upkiResult1 = agent.decryptEnvelope(enc_text, bankcode);
                if (upkiResult1.getResults() == null || upkiResult1.getReturnCode() != 0) {
                    Assert.fail("���������ŷ�ʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
            } catch (Exception e) {
                Assert.fail("���������ŷ�ʧ�ܣ�" + upkiResult1.getReturnCode() + e.getMessage());
            }
        }
    }

    /**
     * ���������ŷ⣬����Ϊnull����ַ�
     */
    @Test(groups = "abcjew.decryptenvelope.normal", dataProvider = "emptys-parameter", dataProviderClass =
            NetSignDataProvider.class)
    public void testDecryptEnvelope_04(String enc_text) {
        System.out.println("���������ŷ⣨decryptEnvelope��������Ϊnull����ַ�");

        String sCertDN = "CN=c020crlfbdIssueModeHTTP";
        UpkiResult upkiResult = null;
        // ���������ŷ�
        try {
            upkiResult = agent.decryptEnvelope(enc_text, sCertDN);
            if (upkiResult.getReturnCode() != -100212 && -1011 != upkiResult.getReturnCode()) {
                Assert.fail("���������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + e.getMessage());
        }
    }

    /**
     * ���������ŷ⣬DN/SN/BankCodeΪnull
     */
    @Test(groups = "abcjew.decryptenvelope.normal", dataProvider = "symmalg-allcert-dn", dataProviderClass =
            NetSignDataProvider.class)
    public void testDecryptEnvelope_05(String sAlg, String str) {
        System.out.println("���������ŷ⣨decryptEnvelope����DN/SN/BankCodeΪnull");

        String[] split = str.split("%");
        String sCertDN = split[0];
        String sPublicKey = split[1];
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        String enc_text = null;
        if ("DESEde".equals(sAlg)) {
            sAlg = "3DES";
        }
        // ���������ŷ�
        try {
            upkiResult = agent.encryptEnvelope(pOrgData, sCertDN, sAlg, sPublicKey);
            enc_text = upkiResult.getResults().get(UpkiResult.ENC_TEXT).toString();
            if (upkiResult.getResults() == null || upkiResult.getReturnCode() != 0) {
                Assert.fail("���������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + e.getMessage());
        }
        // ���������ŷ�
        try {
            if (enc_text != null && !enc_text.isEmpty()) {
                upkiResult1 = agent.decryptEnvelope(enc_text, null);
                if (upkiResult1.getResults() == null || upkiResult1.getReturnCode() != 0) {
                    Assert.fail("���������ŷ�ʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
                Reporter.log("���������ŷ⣨decryptEnvelope����DNΪnull,���Խ��ܳɹ�");
            }
        } catch (Exception e) {
            Assert.fail("���������ŷ�ʧ�ܣ�" + upkiResult1.getReturnCode() + e.getMessage());
        }
    }

    /**
     * ���������ŷ⣬DN/SN/BankCodeΪ��
     */
    @Test(groups = "abcjew.decryptenvelope.normal", dataProvider = "symmalg-allcert-dn", dataProviderClass =
            NetSignDataProvider.class)
    public void testDecryptEnvelope_06(String sAlg, String str) {
        System.out.println("���������ŷ⣨decryptEnvelope����DN/SN/BankCodeΪ���ַ�");

        String[] split = str.split("%");
        String sCertDN = split[0];
        String sPublicKey = split[1];
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        String enc_text = null;
        if ("DESEde".equals(sAlg)) {
            sAlg = "3DES";
        }
        // ���������ŷ�
        try {
            upkiResult = agent.encryptEnvelope(pOrgData, sCertDN, sAlg, sPublicKey);
            enc_text = upkiResult.getResults().get(UpkiResult.ENC_TEXT).toString();
            if (upkiResult.getResults() == null || upkiResult.getReturnCode() != 0) {
                Assert.fail("���������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + e.getMessage());
        }
        // ���������ŷ�
        try {
            if (enc_text != null && !enc_text.isEmpty()) {
                upkiResult1 = agent.decryptEnvelope(enc_text, "");
                if (upkiResult1.getResults() == null || upkiResult1.getReturnCode() != 0) {
                    Assert.fail("���������ŷ�ʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
                Reporter.log("���������ŷ⣨decryptEnvelope����DNΪ��,���Խ��ܳɹ�");
            }
        } catch (Exception e) {
            Assert.fail("���������ŷ�ʧ�ܣ�" + upkiResult1.getReturnCode() + e.getMessage());
        }
    }

    /**
     * ���������ŷ⣬DN�����ʹ��֤�鲻ƥ��
     */
    @Test(groups = "abcjew.decryptenvelope.normal", dataProvider = "symmalg-allcert-dn", dataProviderClass =
            NetSignDataProvider.class)
    public void testDecryptEnvelope_07(String sAlg, String str) {
        System.out.println("���������ŷ⣨decryptEnvelope����DN�����ʹ��֤�鲻ƥ��");

        String[] split = str.split("%");
        String sCertDN = split[0];
        String sPublicKey = split[1];
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        String enc_text = null;
        if ("DESEde".equals(sAlg)) {
            sAlg = "3DES";
        }
        // ���������ŷ�
        try {
            upkiResult = agent.encryptEnvelope(pOrgData, sCertDN, sAlg, sPublicKey);
            enc_text = upkiResult.getResults().get(UpkiResult.ENC_TEXT).toString();
            if (upkiResult.getResults() == null || upkiResult.getReturnCode() != 0) {
                Assert.fail("���������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + e.getMessage());
        }
        // ���������ŷ�
        try {
            if (enc_text != null && !enc_text.isEmpty()) {
                upkiResult1 = agent.decryptEnvelope(enc_text, "CN=123");
                if (upkiResult1.getResults() == null || upkiResult1.getReturnCode() != 0) {
                    Assert.fail("���������ŷ�ʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
                Reporter.log("���������ŷ⣨decryptEnvelope����DN�����ʱʹ��֤�鲻ƥ��,�ܹ����ܳɹ�");
            }
        } catch (Exception e) {
            Assert.fail("���������ŷ�ʧ�ܣ�" + upkiResult1.getReturnCode() + e.getMessage());
        }
    }

    /**
     * ���������ŷ⣬���Ĵ۸�
     */
    @Test(groups = "abcjew.decryptenvelope.normal", dataProvider = "symmalg-allcert-dn", dataProviderClass =
            NetSignDataProvider.class)
    public void testDecryptEnvelope_08(String sAlg, String str) {
        System.out.println("���������ŷ⣨decryptEnvelope�������Ĵ۸�");

        String[] split = str.split("%");
        String sCertDN = split[0];
        String sPublicKey = split[1];
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        String enc_text = null;
        if ("DESEde".equals(sAlg)) {
            sAlg = "3DES";
        }
        // ���������ŷ�
        try {
            upkiResult = agent.encryptEnvelope(pOrgData, sCertDN, sAlg, sPublicKey);
            enc_text = upkiResult.getResults().get(UpkiResult.ENC_TEXT).toString();
            if (upkiResult.getResults() == null || upkiResult.getReturnCode() != 0) {
                Assert.fail("���������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���������ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + e.getMessage());
        }
        // ���������ŷ�
        try {
            if (enc_text != null && !enc_text.isEmpty()) {
                StringBuilder stringBuilder = new StringBuilder(enc_text);
                stringBuilder.replace(5, 10, "abcdef");
                enc_text = new String(stringBuilder);
                upkiResult1 = agent.decryptEnvelope(enc_text, sCertDN);
                if (upkiResult1.getReturnCode() != -100212) {
                    Assert.fail("���������ŷ�ʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
            }
        } catch (Exception e) {
            Assert.fail("���������ŷ�ʧ�ܣ�" + upkiResult1.getReturnCode() + e.getMessage());
        }
    }
}
