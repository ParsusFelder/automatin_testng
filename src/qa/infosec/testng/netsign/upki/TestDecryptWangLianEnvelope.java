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
 * @ClassName: TestDecryptWangLianEnvelope
 * @date 2020-03-02 18:06
 * @Description: ����������ʽ�����ŷ�
 * <p>�������ǵ㣺</p>
 * <p>1������������ʽ�����ŷ⣨decryptWangLianEnvelope��,�Գ��㷨ΪSM4/AES</p>
 * <p>2������������ʽ�����ŷ⣨decryptWangLianEnvelope��,ʹ��֤��SN</p>
 * <p>3������������ʽ�����ŷ⣨decryptWangLianEnvelope��,ʹ��֤��BankCode</p>
 * <p>4������������ʽ�����ŷ⣨decryptWangLianEnvelope��,ʹ����˽Կ֤���BankCode</p>
 * <p>5������������ʽ�����ŷ⣨decryptWangLianEnvelope��,����Ϊ��</p>
 * <p>6������������ʽ�����ŷ⣨decryptWangLianEnvelope��,���Ĵ۸�</p>
 * <p>7������������ʽ�����ŷ⣨decryptWangLianEnvelope��,DNΪ��</p>
 * <p>8������������ʽ�����ŷ⣨decryptWangLianEnvelope��,DNΪnull</p>
 * <p>9������������ʽ�����ŷ⣨decryptWangLianEnvelope��,����DN��ƥ��</p>
 */
@Test(groups = "abcjew.decryptwanglianenvelope")
public class TestDecryptWangLianEnvelope {
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
     * ����������ʽ�����ŷ�,�Գ��㷨ΪSM4/AES
     *
     * @param sCertDN ֤��DN
     * @param sAlg    �Գ��㷨
     */
    @Test(groups = "abcjew.decryptwanglianenvelope.normal", dataProvider = "salg-16-alldn", dataProviderClass =
            NetSignDataProvider.class)
    public void testDecryptWangLianEnvelope_01(String sCertDN, String sAlg) {
        System.out.println("����������ʽ�����ŷ⣨decryptWangLianEnvelope��,�Գ��㷨ΪSM4/AES");

        byte[][] pOrgData = new byte[2][];
        pOrgData[0] = Utils.getRandomString(64).getBytes();
        pOrgData[1] = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        // ����������ʽ�����ŷ�
        try {
            upkiResult = agent.encryptWangLianEnvelope(pOrgData, sCertDN, sAlg);
            Object bool_result = upkiResult.getResults().get(UpkiResult.BOOL_RESULT);
            if (!"true".equals(bool_result) && upkiResult.getReturnCode() != 0) {
                Assert.fail("����������ʽ�����ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("����������ʽ�����ŷ�ʧ�ܣ�" + e.getMessage());
        }
        // ����������ʽ�����ŷ�
        try {
            String[] strs = (String[]) upkiResult.getResults().get(UpkiResult.ENC_WANGLIAN_ENVELOPE);
            UpkiResult upkiResult1 = agent.decryptWangLianEnvelope(strs, sCertDN);
            Object bool_result1 = upkiResult1.getResults().get(UpkiResult.BOOL_RESULT);
            if (!"true".equals(bool_result1) && upkiResult1.getReturnCode() != 0) {
                Assert.fail("����������ʽ�����ŷ�ʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("����������ʽ�����ŷ�ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ����������ʽ�����ŷ�,ʹ��֤��SN
     *
     * @param sCertSN ֤��SN
     * @param sAlg    �Գ��㷨
     */
    @Test(groups = "abcjew.decryptwanglianenvelope.normal", dataProvider = "salg-16-allsn", dataProviderClass =
            NetSignDataProvider.class)
    public void testDecryptWangLianEnvelope_02(String sCertSN, String sAlg) {
        System.out.println("����������ʽ�����ŷ⣨decryptWangLianEnvelope��,ʹ��֤��SN");

        byte[][] pOrgData = new byte[2][];
        pOrgData[0] = Utils.getRandomString(64).getBytes();
        pOrgData[1] = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;

        // ����������ʽ�����ŷ�
        try {
            upkiResult = agent.encryptWangLianEnvelope(pOrgData, sCertSN, sAlg);
            Object bool_result = upkiResult.getResults().get(UpkiResult.BOOL_RESULT);
            if (!"true".equals(bool_result) && upkiResult.getReturnCode() != 0) {
                Assert.fail("����������ʽ�����ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("����������ʽ�����ŷ�ʧ�ܣ�" + e.getMessage());
        }
        // ����������ʽ�����ŷ�
        try {
            String[] strs = (String[]) upkiResult.getResults().get(UpkiResult.ENC_WANGLIAN_ENVELOPE);
            UpkiResult upkiResult1 = agent.decryptWangLianEnvelope(strs, sCertSN);
            Object bool_result1 = upkiResult1.getResults().get(UpkiResult.BOOL_RESULT);
            if (!"true".equals(bool_result1) && upkiResult1.getReturnCode() != 0) {
                Assert.fail("����������ʽ�����ŷ�ʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("����������ʽ�����ŷ�ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ����������ʽ�����ŷ�,ʹ��֤��BankCode
     *
     * @param sCertBankCode ֤��BankCode
     * @param sAlg          �Գ��㷨
     */
    @Test(groups = "abcjew.decryptwanglianenvelope.normal", dataProvider = "salg-16-allbankcode", dataProviderClass =
            NetSignDataProvider.class)
    public void testDecryptWangLianEnvelope_03(String sCertBankCode, String sAlg) {
        System.out.println("����������ʽ�����ŷ⣨decryptWangLianEnvelope��,ʹ��֤��BankCode");

        byte[][] pOrgData = new byte[2][];
        pOrgData[0] = Utils.getRandomString(64).getBytes();
        pOrgData[1] = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        if ("10year".equals(sCertBankCode) || "RSARoot2048".equals(sCertBankCode)) {
            return;
        }
        // ����������ʽ�����ŷ�
        try {
            upkiResult = agent.encryptWangLianEnvelope(pOrgData, sCertBankCode, sAlg);
            Object bool_result = upkiResult.getResults().get(UpkiResult.BOOL_RESULT);
            if (!"true".equals(bool_result) && upkiResult.getReturnCode() != 0) {
                Assert.fail("����������ʽ�����ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("����������ʽ�����ŷ�ʧ�ܣ�" + e.getMessage());
        }
        // ����������ʽ�����ŷ�
        try {
            String[] strs = (String[]) upkiResult.getResults().get(UpkiResult.ENC_WANGLIAN_ENVELOPE);
            UpkiResult upkiResult1 = agent.decryptWangLianEnvelope(strs, sCertBankCode);
            Object bool_result1 = upkiResult1.getResults().get(UpkiResult.BOOL_RESULT);
            if (!"true".equals(bool_result1) && upkiResult1.getReturnCode() != 0) {
                Assert.fail("����������ʽ�����ŷ�ʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("����������ʽ�����ŷ�ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ����������ʽ�����ŷ�,ʹ����˽Կ֤���BankCode
     */
    @Test(groups = "abcjew.decryptwanglianenvelope.normal")
    public void testDecryptWangLianEnvelope_04() {
        System.out.println("����������ʽ�����ŷ⣨decryptWangLianEnvelope��,ʹ����˽Կ֤���BankCode");

        byte[][] pOrgData = new byte[2][];
        pOrgData[0] = Utils.getRandomString(64).getBytes();
        pOrgData[1] = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        String sCertBankCode = "RSARoot2048";
        String sAlg = "AES";
        // ����������ʽ�����ŷ�
        try {
            upkiResult = agent.encryptWangLianEnvelope(pOrgData, sCertBankCode, sAlg);
            Object bool_result = upkiResult.getResults().get(UpkiResult.BOOL_RESULT);
            if (!"true".equals(bool_result) && upkiResult.getReturnCode() != 0) {
                Assert.fail("����������ʽ�����ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("����������ʽ�����ŷ�ʧ�ܣ�" + e.getMessage());
        }
        // ����������ʽ�����ŷ�
        try {
            String[] strs = (String[]) upkiResult.getResults().get(UpkiResult.ENC_WANGLIAN_ENVELOPE);
            UpkiResult upkiResult1 = agent.decryptWangLianEnvelope(strs, sCertBankCode);
            if (upkiResult1.getReturnCode() != -100203) {
                Assert.fail("����������ʽ�����ŷ�ʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("����������ʽ�����ŷ�ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ����������ʽ�����ŷ�,ʹ����˽Կ֤���BankCode
     */
    @Test(groups = "abcjew.decryptwanglianenvelope.normal", dataProvider = "emptys-parameter", dataProviderClass =
            NetSignDataProvider.class)
    public void testDecryptWangLianEnvelope_05(String str) {
        System.out.println("����������ʽ�����ŷ⣨decryptWangLianEnvelope��,����Ϊ��");

        byte[][] pOrgData = new byte[2][];
        pOrgData[0] = Utils.getRandomString(64).getBytes();
        pOrgData[1] = Utils.getRandomString(64).getBytes();
        String sCertBankCode = "CN=c020crlfbdIssueModeHTTP";

        // ����������ʽ�����ŷ�
        try {
            String[] strs = new String[1];
            strs[0] = str;
            UpkiResult upkiResult1 = agent.decryptWangLianEnvelope(strs, sCertBankCode);
            if (upkiResult1.getReturnCode() != -1022) {
                Assert.fail("����������ʽ�����ŷ�ʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("����������ʽ�����ŷ�ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ����������ʽ�����ŷ�,���Ĵ۸�
     *
     * @param sCertDN ֤��DN
     * @param sAlg    �Գ��㷨
     */
    @Test(groups = "abcjew.decryptwanglianenvelope.normal", dataProvider = "salg-16-alldn", dataProviderClass =
            NetSignDataProvider.class)
    public void testDecryptWangLianEnvelope_06(String sCertDN, String sAlg) {
        System.out.println("����������ʽ�����ŷ⣨decryptWangLianEnvelope��,���Ĵ۸�");

        byte[][] pOrgData = new byte[2][];
        pOrgData[0] = Utils.getRandomString(64).getBytes();
        pOrgData[1] = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        // ����������ʽ�����ŷ�
        try {
            upkiResult = agent.encryptWangLianEnvelope(pOrgData, sCertDN, sAlg);
            Object bool_result = upkiResult.getResults().get(UpkiResult.BOOL_RESULT);
            if (!"true".equals(bool_result) && upkiResult.getReturnCode() != 0) {
                Assert.fail("����������ʽ�����ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("����������ʽ�����ŷ�ʧ�ܣ�" + e.getMessage());
        }
        // ����������ʽ�����ŷ�
        try {
            String[] strs = (String[]) upkiResult.getResults().get(UpkiResult.ENC_WANGLIAN_ENVELOPE);
            // �۸ļ�������
            strs[0] = Utils.modifyData(strs[0], 5, 10, "abcdef");
            strs[1] = Utils.modifyData(strs[1], 5, 10, "zhaoyongzhi");

            UpkiResult upkiResult1 = agent.decryptWangLianEnvelope(strs, sCertDN);
            if (upkiResult1.getReturnCode() != -100212) {
                Assert.fail("����������ʽ�����ŷ�ʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("����������ʽ�����ŷ�ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ����������ʽ�����ŷ�,DNΪ��
     *
     * @param sCertDN ֤��DN
     * @param sAlg    �Գ��㷨
     */
    @Test(groups = "abcjew.decryptwanglianenvelope.normal", dataProvider = "salg-16-alldn", dataProviderClass =
            NetSignDataProvider.class)
    public void testDecryptWangLianEnvelope_07(String sCertDN, String sAlg) {
        System.out.println("����������ʽ�����ŷ⣨decryptWangLianEnvelope��,DNΪ��");

        byte[][] pOrgData = new byte[2][];
        pOrgData[0] = Utils.getRandomString(64).getBytes();
        pOrgData[1] = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        // ����������ʽ�����ŷ�
        try {
            upkiResult = agent.encryptWangLianEnvelope(pOrgData, sCertDN, sAlg);
            Object bool_result = upkiResult.getResults().get(UpkiResult.BOOL_RESULT);
            if (!"true".equals(bool_result) && upkiResult.getReturnCode() != 0) {
                Assert.fail("����������ʽ�����ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("����������ʽ�����ŷ�ʧ�ܣ�" + e.getMessage());
        }
        // ����������ʽ�����ŷ�
        try {
            String[] strs = (String[]) upkiResult.getResults().get(UpkiResult.ENC_WANGLIAN_ENVELOPE);
            UpkiResult upkiResult1 = agent.decryptWangLianEnvelope(strs, "");
            if (upkiResult1.getReturnCode() != -100212) {
                if (upkiResult1.getReturnCode() != 0) {
                    Assert.fail("����������ʽ�����ŷ�ʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
                Reporter.log("����������ʽ�����ŷ⣨decryptWangLianEnvelope��������������ʽ�����ŷ⣬��DN������ַ�ʱ����ʹ�ü���֤���б����õĵ�һ��֤��");
            }
        } catch (Exception e) {
            Assert.fail("����������ʽ�����ŷ�ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ����������ʽ�����ŷ�,DNΪnull
     *
     * @param sCertDN ֤��null
     * @param sAlg    �Գ��㷨
     */
    @Test(groups = "abcjew.decryptwanglianenvelope.normal", dataProvider = "salg-16-alldn", dataProviderClass =
            NetSignDataProvider.class)
    public void testDecryptWangLianEnvelope_08(String sCertDN, String sAlg) {
        System.out.println("����������ʽ�����ŷ⣨decryptWangLianEnvelope��,DNΪnull");

        byte[][] pOrgData = new byte[2][];
        pOrgData[0] = Utils.getRandomString(64).getBytes();
        pOrgData[1] = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        // ����������ʽ�����ŷ�
        try {
            upkiResult = agent.encryptWangLianEnvelope(pOrgData, sCertDN, sAlg);
            Object bool_result = upkiResult.getResults().get(UpkiResult.BOOL_RESULT);
            if (!"true".equals(bool_result) && upkiResult.getReturnCode() != 0) {
                Assert.fail("����������ʽ�����ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("����������ʽ�����ŷ�ʧ�ܣ�" + e.getMessage());
        }
        // ����������ʽ�����ŷ�
        try {
            String[] strs = (String[]) upkiResult.getResults().get(UpkiResult.ENC_WANGLIAN_ENVELOPE);
            UpkiResult upkiResult1 = agent.decryptWangLianEnvelope(strs, null);
            if (upkiResult1.getReturnCode() != -100212) {
                if (upkiResult1.getReturnCode() != 0) {
                    Assert.fail("����������ʽ�����ŷ�ʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
                Reporter.log("����������ʽ�����ŷ⣨decryptWangLianEnvelope��������������ʽ�����ŷ⣬��DN������ַ�ʱ����ʹ�ü���֤���б����õĵ�һ��֤��");
            }
        } catch (Exception e) {
            Assert.fail("����������ʽ�����ŷ�ʧ�ܣ�" + e.getMessage());
        }
    }

    /**
     * ����������ʽ�����ŷ�,����DN��ƥ��
     *
     * @param sCertDN ֤��null
     * @param sAlg    �Գ��㷨
     */
    @Test(groups = "abcjew.decryptwanglianenvelope.normal", dataProvider = "salg-16-alldn", dataProviderClass =
            NetSignDataProvider.class)
    public void testDecryptWangLianEnvelope_09(String sCertDN, String sAlg) {
        System.out.println("����������ʽ�����ŷ⣨decryptWangLianEnvelope��,����DN��ƥ��");

        byte[][] pOrgData = new byte[2][];
        pOrgData[0] = Utils.getRandomString(64).getBytes();
        pOrgData[1] = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        // ����������ʽ�����ŷ�
        try {
            upkiResult = agent.encryptWangLianEnvelope(pOrgData, sCertDN, sAlg);
            Object bool_result = upkiResult.getResults().get(UpkiResult.BOOL_RESULT);
            if (!"true".equals(bool_result) && upkiResult.getReturnCode() != 0) {
                Assert.fail("����������ʽ�����ŷ�ʧ�ܣ�" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("����������ʽ�����ŷ�ʧ�ܣ�" + e.getMessage());
        }
        // ����������ʽ�����ŷ�
        try {
            String[] strs = (String[]) upkiResult.getResults().get(UpkiResult.ENC_WANGLIAN_ENVELOPE);
            UpkiResult upkiResult1 = agent.decryptWangLianEnvelope(strs, "CN=123");
            if (upkiResult1.getReturnCode() != -100203) {
                Assert.fail("����������ʽ�����ŷ�ʧ�ܣ�" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("����������ʽ�����ŷ�ʧ�ܣ�" + e.getMessage());
        }
    }
}
