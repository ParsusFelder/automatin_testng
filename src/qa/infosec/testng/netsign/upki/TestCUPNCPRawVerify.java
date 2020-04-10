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
 * @ClassName: TestCUPNCPRawVerify
 * @date 2020-03-02 18:19
 * @Description: ���������޿�֧����ǩ��
 * <p>�������ǵ㣺</p>
 * <p>1�����������޿�֧����ǩ����CUPNCPRawVerify����ʹ������RSA֤��DN��ǩ</p>
 * <p>2�����������޿�֧����ǩ����CUPNCPRawVerify����ʹ������RSA֤��DN��ǩ</p>
 * <p>3�����������޿�֧����ǩ����CUPNCPRawVerify����ʹ�ù���RSA֤��DN��ǩ</p>
 * <p>4�����������޿�֧����ǩ����CUPNCPRawVerify����ʹ������RSA֤��SN��ǩ</p>
 * <p>5�����������޿�֧����ǩ����CUPNCPRawVerify����ʹ������RSA֤��Bankcode��ǩ</p>
 * <p>6�����������޿�֧����ǩ����CUPNCPRawVerify����ʹ������RSA֤��Bankcode��ǩ</p>
 * <p>7�����������޿�֧����ǩ����CUPNCPRawVerify����ʹ�ù���RSA֤��Bankcode��ǩ</p>
 * <p>8�����������޿�֧����ǩ����CUPNCPRawVerify����ʹ������SM2֤��DN��ǩ</p>
 * <p>9�����������޿�֧����ǩ����CUPNCPRawVerify����ʹ������SM2֤��DN��ǩ</p>
 * <p>10�����������޿�֧����ǩ����CUPNCPRawVerify����ʹ�ù���SM2֤��DN��ǩ</p>
 * <p>11�����������޿�֧����ǩ����CUPNCPRawVerify����ʹ������SM2֤��SN��ǩ</p>
 * <p>12�����������޿�֧����ǩ����CUPNCPRawVerify����ʹ������SM2֤��Bankcode��ǩ</p>
 * <p>13�����������޿�֧����ǩ����CUPNCPRawVerify����ʹ������SM2֤��Bankcode��ǩ</p>
 * <p>14�����������޿�֧����ǩ����CUPNCPRawVerify����ʹ�ù���SM2֤��Bankcode��ǩ</p>
 * <p>15�����������޿�֧����ǩ����CUPNCPRawVerify����ԭ��Ϊnull</p>
 * <p>16�����������޿�֧����ǩ����CUPNCPRawVerify����ԭ�ı��۸�</p>
 * <p>17�����������޿�֧����ǩ����CUPNCPRawVerify��������Ϊ�ջ�null</p>
 * <p>18�����������޿�֧����ǩ����CUPNCPRawVerify�������Ĵ۸�</p>
 * <p>19�����������޿�֧����ǩ����CUPNCPRawVerify����DNΪ�ջ�null</p>
 * <p>20�����������޿�֧����ǩ����CUPNCPRawVerify������ǩDN��ǩ��DN��һ��</p>
 * <p>21�����������޿�֧����ǩ����CUPNCPRawVerify����ժҪ�㷨Ϊ�ջ�null</p>
 * <p>22�����������޿�֧����ǩ����CUPNCPRawVerify������ǩժҪ�㷨��ǩ��ժҪ�㷨��һ��</p>
 * <p>23�����������޿�֧����ǩ����CUPNCPRawVerify����ժҪ�㷨����</p>
 */
@Test(groups = "abcjew.cupncprawverify")
public class TestCUPNCPRawVerify {
    static String ip, port, password;
    static String host, sftp_port, sftp_password, sftp_user;

    NetSignServerInit init = new NetSignServerInit();
    UpkiAgent agent;
    SFTPFile tmp = new SFTPFile();

    {
        // ����netsignconfig.properties�����ļ�����ȡ������Ϣ,confpath=null ʹ��Ĭ��·��
        Map<String, String> map = ParseFile.parseProperties(null);
        ip = map.get("ServerIP");
        port = map.get("ServerPortPBC2G");
        password = map.get("APIPassword");
        host = map.get("sftp_ip");
        sftp_port = map.get("sftp_port");
        sftp_user = map.get("sftp_user");
        sftp_password = map.get("sftp_password");

        agent = init.upkiStart(ip, port, password, true, 20);
        tmp.downFile(sftp_user, host, sftp_port, sftp_password, ParameterUtil.sftpkeystorepath,
                ParameterUtil.keystorepath);
        System.out.println("NetSignServerInit OK");
    }

    /**
     * ���������޿�֧����ǩ����CUPNCPRawVerify����ʹ������RSA֤��DN��ǩ
     *
     * @param alg ժҪ�㷨
     * @param dn  ����RSA֤��DN
     */
    @Test(groups = "abcjew.cupncprawverify.normal", dataProvider = "normal-rsa-dn-dalg", dataProviderClass =
            NetSignDataProvider.class)
    public void testCUPNCPRawVerify_01(String dn, String alg) {
        System.out.println("���������޿�֧����ǩ����CUPNCPRawVerify����ʹ������RSA֤��DN��ǩ");
        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        boolean bool_result;
        String sign_text = null;
        try {
            upkiResult = agent.CUPNCPRawSign(plainText, dn, alg);
            bool_result = upkiResult.getBoolResult();
            if (!bool_result || upkiResult.getReturnCode() != 0) {
                Assert.fail("���������޿�֧����ǩ����CUPNCPRawSign����ǩ��ʧ��" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            if (upkiResult != null) {
                Assert.fail("���������޿�֧����ǩ����CUPNCPRawSign����ǩ��ʧ��" + upkiResult.getReturnCode() + upkiResult.getReturnContent() + e.getMessage());
            }
        }

        try {
            if (upkiResult != null) {
                sign_text = upkiResult.getResults().get("sign_text").toString();
            }
            upkiResult1 = agent.CUPNCPRawVerify(plainText, sign_text, dn, alg);
            bool_result = upkiResult1.getBoolResult();
            if (!bool_result || upkiResult1.getReturnCode() != 0) {
                Assert.fail("���������޿�֧����ǩ����CUPNCPRawVerify������ǩ��ʧ��" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            if (upkiResult1 != null) {
                Assert.fail("���������޿�֧����ǩ����CUPNCPRawSign����ǩ��ʧ��" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent() + e.getMessage());
            }
        }
    }

    /**
     * ���������޿�֧����ǩ����CUPNCPRawVerify����ʹ������RSA֤��DN��ǩ
     *
     * @param alg ժҪ�㷨
     * @param dn  ����RSA֤��DN
     */
    @Test(groups = "abcjew.cupncprawverify.normal", dataProvider = "revoke-rsa-dn-dalg", dataProviderClass =
            NetSignDataProvider.class)
    public void testCUPNCPRawVerify_02(String dn, String alg) {
        System.out.println("���������޿�֧����ǩ����CUPNCPRawVerify����ʹ������RSA֤��DN��ǩ");
        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        boolean bool_result;
        String sign_text = null;
        try {
            upkiResult = agent.CUPNCPRawSign(plainText, dn, alg);
            bool_result = upkiResult.getBoolResult();
            if (!bool_result || upkiResult.getReturnCode() != 0) {
                Assert.fail("���������޿�֧����ǩ����CUPNCPRawSign����ǩ��ʧ��" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���������޿�֧����ǩ����CUPNCPRawSign����ǩ��ʧ��" + upkiResult.getReturnCode() + upkiResult.getReturnContent() + e.getMessage());
        }

        try {
            if (upkiResult != null) {
                sign_text = upkiResult.getResults().get("sign_text").toString();
            }
            upkiResult1 = agent.CUPNCPRawVerify(plainText, sign_text, dn, alg);
            bool_result = upkiResult1.getBoolResult();
            if (!"C=CN,O=infosec,OU=test3,CN=C020revokeMatchingAnyCrlfbd".equals(dn) && !("C=CN,O=infosec," +
                    "CN=C020revokedNocrlfile").equals(dn)) {
                if (bool_result || upkiResult1.getReturnCode() != -100108) {
                    Assert.fail("���������޿�֧����ǩ����CUPNCPRawVerify������ǩ��ʧ��" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
            }
        } catch (Exception e) {
            Assert.fail("���������޿�֧����ǩ����CUPNCPRawVerify������ǩ��ʧ��" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
        }
    }

    /**
     * ���������޿�֧����ǩ����CUPNCPRawVerify����ʹ�ù���RSA֤��DN��ǩ
     *
     * @param alg ժҪ�㷨
     * @param dn  ����RSA֤��DN
     */
    @Test(groups = "abcjew.cupncprawverify.normal", dataProvider = "expire-rsa-dn-dalg", dataProviderClass =
            NetSignDataProvider.class)
    public void testCUPNCPRawVerify_03(String dn, String alg) {
        System.out.println("���������޿�֧����ǩ����CUPNCPRawVerify����ʹ������RSA֤��DN��ǩ");
        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        boolean bool_result;
        String sign_text = null;
        try {
            upkiResult = agent.CUPNCPRawSign(plainText, dn, alg);
            bool_result = upkiResult.getBoolResult();
            if (!bool_result || upkiResult.getReturnCode() != 0) {
                Assert.fail("���������޿�֧����ǩ����CUPNCPRawSign����ǩ��ʧ��" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���������޿�֧����ǩ����CUPNCPRawSign����ǩ��ʧ��" + upkiResult.getReturnCode() + upkiResult.getReturnContent() + e.getMessage());
        }

        try {
            if (upkiResult != null) {
                sign_text = upkiResult.getResults().get("sign_text").toString();
            }
            upkiResult1 = agent.CUPNCPRawVerify(plainText, sign_text, dn, alg);
            bool_result = upkiResult1.getBoolResult();
            if (bool_result || upkiResult1.getReturnCode() != -100106) {
                Assert.fail("���������޿�֧����ǩ����CUPNCPRawVerify������ǩ��ʧ��" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���������޿�֧����ǩ����CUPNCPRawVerify������ǩ��ʧ��" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
        }
    }

    /**
     * ���������޿�֧����ǩ����CUPNCPRawVerify����ʹ������RSA֤��SN��ǩ
     *
     * @param alg ժҪ�㷨
     * @param sn  ����RSA֤��SN
     */
    @Test(groups = "abcjew.cupncprawverify.normal", dataProvider = "normal-rsa-sn-dalg", dataProviderClass =
            NetSignDataProvider.class)
    public void testCUPNCPRawVerify_04(String sn, String alg) {
        System.out.println("���������޿�֧����ǩ����CUPNCPRawVerify����ʹ������RSA֤��SN��ǩ");
        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        boolean bool_result;
        String sign_text = null;
        try {
            upkiResult = agent.CUPNCPRawSign(plainText, sn, alg);
            bool_result = upkiResult.getBoolResult();
            if (!bool_result || upkiResult.getReturnCode() != 0) {
                Assert.fail("���������޿�֧����ǩ����CUPNCPRawSign����ǩ��ʧ��" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���������޿�֧����ǩ����CUPNCPRawSign����ǩ��ʧ��" + upkiResult.getReturnCode() + upkiResult.getReturnContent() + e.getMessage());
        }

        try {
            if (upkiResult != null) {
                sign_text = upkiResult.getResults().get("sign_text").toString();
            }
            upkiResult1 = agent.CUPNCPRawVerify(plainText, sign_text, sn, alg);
            bool_result = upkiResult1.getBoolResult();
            if (!bool_result || upkiResult1.getReturnCode() != 0) {
                if (upkiResult1.getReturnCode() != -100224) {
                    Assert.fail("���������޿�֧����ǩ����CUPNCPRawVerify������ǩ��ʧ��" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
                Reporter.log("���������޿�֧����ǩ����CUPNCPRawVerify������֧��ʹ��֤��SN��ǩ");
            }
        } catch (Exception e) {
            Assert.fail("���������޿�֧����ǩ����CUPNCPRawVerify������ǩ��ʧ��" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
        }
    }

    /**
     * ���������޿�֧����ǩ����CUPNCPRawVerify����ʹ������RSA֤��Bankcode��ǩ
     *
     * @param alg      ժҪ�㷨
     * @param bankcode ����RSA֤��Bankcode
     */
    @Test(groups = "abcjew.cupncprawverify.normal", dataProvider = "normal-rsa-bankcode-dalg", dataProviderClass =
            NetSignDataProvider.class)
    public void testCUPNCPRawVerify_05(String bankcode, String alg) {
        System.out.println("���������޿�֧����ǩ����CUPNCPRawVerify����ʹ������RSA֤��Bankcode��ǩ");
        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        boolean bool_result;
        String sign_text = null;
        try {
            upkiResult = agent.CUPNCPRawSign(plainText, bankcode, alg);
            bool_result = upkiResult.getBoolResult();
            if (!bool_result || upkiResult.getReturnCode() != 0) {
                Assert.fail("���������޿�֧����ǩ����CUPNCPRawSign����ǩ��ʧ��" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���������޿�֧����ǩ����CUPNCPRawSign����ǩ��ʧ��" + upkiResult.getReturnCode() + upkiResult.getReturnContent() + e.getMessage());
        }

        try {
            if (upkiResult != null) {
                sign_text = upkiResult.getResults().get("sign_text").toString();
            }
            upkiResult1 = agent.CUPNCPRawVerify(plainText, sign_text, bankcode, alg);
            bool_result = upkiResult1.getBoolResult();
            if (!bool_result || upkiResult1.getReturnCode() != 0) {
                Assert.fail("���������޿�֧����ǩ����CUPNCPRawVerify������ǩ��ʧ��" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���������޿�֧����ǩ����CUPNCPRawVerify������ǩ��ʧ��" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
        }
    }

    /**
     * ���������޿�֧����ǩ����CUPNCPRawVerify����ʹ������RSA֤��Bankcode��ǩ
     *
     * @param alg      ժҪ�㷨
     * @param bankcode ����RSA֤��Bankcode
     */
    @Test(groups = "abcjew.cupncprawverify.normal", dataProvider = "revoke-rsa-bankcode-dalg", dataProviderClass =
            NetSignDataProvider.class)
    public void testCUPNCPRawVerify_06(String bankcode, String alg) {
        System.out.println("���������޿�֧����ǩ����CUPNCPRawVerify����ʹ������RSA֤��Bankcode��ǩ");
        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        boolean bool_result;
        String sign_text = null;
        try {
            upkiResult = agent.CUPNCPRawSign(plainText, bankcode, alg);
            bool_result = upkiResult.getBoolResult();
            if (!bool_result || upkiResult.getReturnCode() != 0) {
                Assert.fail("���������޿�֧����ǩ����CUPNCPRawSign����ǩ��ʧ��" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���������޿�֧����ǩ����CUPNCPRawSign����ǩ��ʧ��" + upkiResult.getReturnCode() + upkiResult.getReturnContent() + e.getMessage());
        }

        try {
            if (upkiResult != null) {
                sign_text = upkiResult.getResults().get("sign_text").toString();
            }
            upkiResult1 = agent.CUPNCPRawVerify(plainText, sign_text, bankcode, alg);
            bool_result = upkiResult1.getBoolResult();
            if (!"MatchingAnyCrlfbd".equals(bankcode) && !("C020revokeMatchingAnyCrlfbd").equals(bankcode) && !(
                    "C020revokedNocrlfile").equals(bankcode)) {
                if (bool_result || upkiResult1.getReturnCode() != -100108) {
                    Assert.fail("���������޿�֧����ǩ����CUPNCPRawVerify������ǩ��ʧ��" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
            }
        } catch (Exception e) {
            Assert.fail("���������޿�֧����ǩ����CUPNCPRawVerify������ǩ��ʧ��" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
        }
    }

    /**
     * ���������޿�֧����ǩ����CUPNCPRawVerify����ʹ�ù���RSA֤��Bankcode��ǩ
     *
     * @param alg      ժҪ�㷨
     * @param bankcode ����RSA֤��Bankcode
     */
    @Test(groups = "abcjew.cupncprawverify.normal", dataProvider = "expire-rsa-bankcode-dalg", dataProviderClass =
            NetSignDataProvider.class)
    public void testCUPNCPRawVerify_07(String bankcode, String alg) {
        System.out.println("���������޿�֧����ǩ����CUPNCPRawVerify����ʹ������RSA֤��Bankcode��ǩ");
        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        boolean bool_result;
        String sign_text = null;
        try {
            upkiResult = agent.CUPNCPRawSign(plainText, bankcode, alg);
            bool_result = upkiResult.getBoolResult();
            if (!bool_result || upkiResult.getReturnCode() != 0) {
                Assert.fail("���������޿�֧����ǩ����CUPNCPRawSign����ǩ��ʧ��" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���������޿�֧����ǩ����CUPNCPRawSign����ǩ��ʧ��" + upkiResult.getReturnCode() + upkiResult.getReturnContent() + e.getMessage());
        }

        try {
            if (upkiResult != null) {
                sign_text = upkiResult.getResults().get("sign_text").toString();
            }
            upkiResult1 = agent.CUPNCPRawVerify(plainText, sign_text, bankcode, alg);
            bool_result = upkiResult1.getBoolResult();
            if (bool_result || upkiResult1.getReturnCode() != -100106) {
                Assert.fail("���������޿�֧����ǩ����CUPNCPRawVerify������ǩ��ʧ��" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���������޿�֧����ǩ����CUPNCPRawVerify������ǩ��ʧ��" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
        }
    }

    /**
     * ���������޿�֧����ǩ����CUPNCPRawVerify����ʹ������SM2֤��DN��ǩ
     *
     * @param alg ժҪ�㷨
     * @param dn  ����SM2֤��DN
     */
    @Test(groups = "abcjew.cupncprawverify.normal", dataProvider = "normal-sm2-dn-dalg", dataProviderClass =
            NetSignDataProvider.class)
    public void testCUPNCPRawVerify_08(String dn, String alg) {
        System.out.println("���������޿�֧����ǩ����CUPNCPRawVerify����ʹ������SM2֤��DN��ǩ");
        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        boolean bool_result;
        String sign_text = null;
        try {
            upkiResult = agent.CUPNCPRawSign(plainText, dn, alg);
            bool_result = upkiResult.getBoolResult();
            if (!bool_result || upkiResult.getReturnCode() != 0) {
                Assert.fail("���������޿�֧����ǩ����CUPNCPRawSign����ǩ��ʧ��" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���������޿�֧����ǩ����CUPNCPRawSign����ǩ��ʧ��" + upkiResult.getReturnCode() + upkiResult.getReturnContent() + e.getMessage());
        }

        try {
            if (upkiResult != null) {
                sign_text = upkiResult.getResults().get("sign_text").toString();
            }
            upkiResult1 = agent.CUPNCPRawVerify(plainText, sign_text, dn, alg);
            bool_result = upkiResult1.getBoolResult();
            if (!bool_result || upkiResult1.getReturnCode() != 0) {
                Assert.fail("���������޿�֧����ǩ����CUPNCPRawVerify������ǩ��ʧ��" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���������޿�֧����ǩ����CUPNCPRawVerify������ǩ��ʧ��" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
        }
    }

    /**
     * ���������޿�֧����ǩ����CUPNCPRawVerify����ʹ������SM2֤��DN��ǩ
     *
     * @param alg ժҪ�㷨
     * @param dn  ����SM2֤��DN
     */
    @Test(groups = "abcjew.cupncprawverify.normal", dataProvider = "revoke-sm2-dn-dalg", dataProviderClass =
            NetSignDataProvider.class)
    public void testCUPNCPRawVerify_09(String dn, String alg) {
        System.out.println("���������޿�֧����ǩ����CUPNCPRawVerify����ʹ������SM2֤��DN��ǩ");
        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        boolean bool_result;
        String sign_text = null;
        try {
            upkiResult = agent.CUPNCPRawSign(plainText, dn, alg);
            bool_result = upkiResult.getBoolResult();
            if (!bool_result || upkiResult.getReturnCode() != 0) {
                Assert.fail("���������޿�֧����ǩ����CUPNCPRawSign����ǩ��ʧ��" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���������޿�֧����ǩ����CUPNCPRawSign����ǩ��ʧ��" + upkiResult.getReturnCode() + upkiResult.getReturnContent() + e.getMessage());
        }

        try {
            if (upkiResult != null) {
                sign_text = upkiResult.getResults().get("sign_text").toString();
            }
            upkiResult1 = agent.CUPNCPRawVerify(plainText, sign_text, dn, alg);
            bool_result = upkiResult1.getBoolResult();
            if (bool_result || upkiResult1.getReturnCode() != -100108) {
                Assert.fail("���������޿�֧����ǩ����CUPNCPRawVerify������ǩ��ʧ��" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���������޿�֧����ǩ����CUPNCPRawVerify������ǩ��ʧ��" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
        }
    }

    /**
     * ���������޿�֧����ǩ����CUPNCPRawVerify����ʹ�ù���SM2֤��DN��ǩ
     *
     * @param alg ժҪ�㷨
     * @param dn  ����SM2֤��DN
     */
    @Test(groups = "abcjew.cupncprawverify.normal", dataProvider = "expire-sm2-dn-dalg", dataProviderClass =
            NetSignDataProvider.class)
    public void testCUPNCPRawVerify_10(String dn, String alg) {
        System.out.println("���������޿�֧����ǩ����CUPNCPRawVerify����ʹ������SM2֤��DN��ǩ");
        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        boolean bool_result;
        String sign_text = null;
        try {
            upkiResult = agent.CUPNCPRawSign(plainText, dn, alg);
            bool_result = upkiResult.getBoolResult();
            if (!bool_result || upkiResult.getReturnCode() != 0) {
                Assert.fail("���������޿�֧����ǩ����CUPNCPRawSign����ǩ��ʧ��" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���������޿�֧����ǩ����CUPNCPRawSign����ǩ��ʧ��" + upkiResult.getReturnCode() + upkiResult.getReturnContent() + e.getMessage());
        }

        try {
            if (upkiResult != null) {
                sign_text = upkiResult.getResults().get("sign_text").toString();
            }
            upkiResult1 = agent.CUPNCPRawVerify(plainText, sign_text, dn, alg);
            bool_result = upkiResult1.getBoolResult();
            if (bool_result || upkiResult1.getReturnCode() != -100106) {
                Assert.fail("���������޿�֧����ǩ����CUPNCPRawVerify������ǩ��ʧ��" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���������޿�֧����ǩ����CUPNCPRawVerify������ǩ��ʧ��" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
        }
    }

    /**
     * ���������޿�֧����ǩ����CUPNCPRawVerify����ʹ������SM2֤��SN��ǩ
     *
     * @param alg ժҪ�㷨
     * @param sn  ����SM2֤��SN
     */
    @Test(groups = "abcjew.cupncprawverify.normal", dataProvider = "normal-sm2-sn-dalg", dataProviderClass =
            NetSignDataProvider.class)
    public void testCUPNCPRawVerify_11(String sn, String alg) {
        System.out.println("���������޿�֧����ǩ����CUPNCPRawVerify����ʹ������SM2֤��SN��ǩ");
        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        boolean bool_result;
        String sign_text = null;
        try {
            upkiResult = agent.CUPNCPRawSign(plainText, sn, alg);
            bool_result = upkiResult.getBoolResult();
            if (!bool_result || upkiResult.getReturnCode() != 0) {
                Assert.fail("���������޿�֧����ǩ����CUPNCPRawSign����ǩ��ʧ��" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���������޿�֧����ǩ����CUPNCPRawSign����ǩ��ʧ��" + upkiResult.getReturnCode() + upkiResult.getReturnContent() + e.getMessage());
        }

        try {
            if (upkiResult != null) {
                sign_text = upkiResult.getResults().get("sign_text").toString();
            }
            upkiResult1 = agent.CUPNCPRawVerify(plainText, sign_text, sn, alg);
            bool_result = upkiResult1.getBoolResult();
            if (!bool_result || upkiResult1.getReturnCode() != 0) {
                if (upkiResult1.getReturnCode() != -100224) {
                    Assert.fail("���������޿�֧����ǩ����CUPNCPRawVerify������ǩ��ʧ��" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
                }
                Reporter.log("���������޿�֧����ǩ����CUPNCPRawVerify������֧��ʹ��֤��SN��ǩ");
            }
        } catch (Exception e) {
            Assert.fail("���������޿�֧����ǩ����CUPNCPRawVerify������ǩ��ʧ��" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
        }
    }

    /**
     * ���������޿�֧����ǩ����CUPNCPRawVerify����ʹ������SM2֤��Bankcode��ǩ
     *
     * @param alg      ժҪ�㷨
     * @param bankcode ����SM2֤��Bankcode
     */
    @Test(groups = "abcjew.cupncprawverify.normal", dataProvider = "normal-sm2-bankcode-dalg", dataProviderClass =
            NetSignDataProvider.class)
    public void testCUPNCPRawVerify_12(String bankcode, String alg) {
        System.out.println("���������޿�֧����ǩ����CUPNCPRawVerify����ʹ������SM2֤��Bankcode��ǩ");
        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        boolean bool_result;
        String sign_text = null;
        try {
            upkiResult = agent.CUPNCPRawSign(plainText, bankcode, alg);
            bool_result = upkiResult.getBoolResult();
            if (!bool_result || upkiResult.getReturnCode() != 0) {
                Assert.fail("���������޿�֧����ǩ����CUPNCPRawSign����ǩ��ʧ��" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���������޿�֧����ǩ����CUPNCPRawSign����ǩ��ʧ��" + upkiResult.getReturnCode() + upkiResult.getReturnContent() + e.getMessage());
        }

        try {
            if (upkiResult != null) {
                sign_text = upkiResult.getResults().get("sign_text").toString();
            }
            upkiResult1 = agent.CUPNCPRawVerify(plainText, sign_text, bankcode, alg);
            bool_result = upkiResult1.getBoolResult();
            if (!bool_result || upkiResult1.getReturnCode() != 0) {
                Assert.fail("���������޿�֧����ǩ����CUPNCPRawVerify������ǩ��ʧ��" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���������޿�֧����ǩ����CUPNCPRawVerify������ǩ��ʧ��" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
        }
    }

    /**
     * ���������޿�֧����ǩ����CUPNCPRawVerify����ʹ������SM2֤��Bankcode��ǩ
     *
     * @param alg      ժҪ�㷨
     * @param bankcode ����SM2֤��Bankcode
     */
    @Test(groups = "abcjew.cupncprawverify.normal", dataProvider = "revoke-sm2-bankcode-dalg", dataProviderClass =
            NetSignDataProvider.class)
    public void testCUPNCPRawVerify_13(String bankcode, String alg) {
        System.out.println("���������޿�֧����ǩ����CUPNCPRawVerify����ʹ������SM2֤��Bankcode��ǩ");
        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        boolean bool_result;
        String sign_text = null;
        try {
            upkiResult = agent.CUPNCPRawSign(plainText, bankcode, alg);
            bool_result = upkiResult.getBoolResult();
            if (!bool_result || upkiResult.getReturnCode() != 0) {
                Assert.fail("���������޿�֧����ǩ����CUPNCPRawSign����ǩ��ʧ��" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���������޿�֧����ǩ����CUPNCPRawSign����ǩ��ʧ��" + upkiResult.getReturnCode() + upkiResult.getReturnContent() + e.getMessage());
        }

        try {
            if (upkiResult != null) {
                sign_text = upkiResult.getResults().get("sign_text").toString();
            }
            upkiResult1 = agent.CUPNCPRawVerify(plainText, sign_text, bankcode, alg);
            bool_result = upkiResult1.getBoolResult();
            if (bool_result || upkiResult1.getReturnCode() != -100108) {
                Assert.fail("���������޿�֧����ǩ����CUPNCPRawVerify������ǩ��ʧ��" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���������޿�֧����ǩ����CUPNCPRawVerify������ǩ��ʧ��" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
        }
    }

    /**
     * ���������޿�֧����ǩ����CUPNCPRawVerify����ʹ�ù���SM2֤��Bankcode��ǩ
     *
     * @param alg      ժҪ�㷨
     * @param bankcode ����SM2֤��Bankcode
     */
    @Test(groups = "abcjew.cupncprawverify.normal", dataProvider = "expire-sm2-bankcode-dalg", dataProviderClass =
            NetSignDataProvider.class)
    public void testCUPNCPRawVerify_14(String bankcode, String alg) {
        System.out.println("���������޿�֧����ǩ����CUPNCPRawVerify����ʹ������SM2֤��Bankcode��ǩ");
        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        boolean bool_result;
        String sign_text = null;
        try {
            upkiResult = agent.CUPNCPRawSign(plainText, bankcode, alg);
            bool_result = upkiResult.getBoolResult();
            if (!bool_result || upkiResult.getReturnCode() != 0) {
                Assert.fail("���������޿�֧����ǩ����CUPNCPRawSign����ǩ��ʧ��" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���������޿�֧����ǩ����CUPNCPRawSign����ǩ��ʧ��" + upkiResult.getReturnCode() + upkiResult.getReturnContent() + e.getMessage());
        }

        try {
            if (upkiResult != null) {
                sign_text = upkiResult.getResults().get("sign_text").toString();
            }
            upkiResult1 = agent.CUPNCPRawVerify(plainText, sign_text, bankcode, alg);
            bool_result = upkiResult1.getBoolResult();
            if (bool_result || upkiResult1.getReturnCode() != -100106) {
                Assert.fail("���������޿�֧����ǩ����CUPNCPRawVerify������ǩ��ʧ��" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���������޿�֧����ǩ����CUPNCPRawVerify������ǩ��ʧ��" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
        }
    }

    /**
     * ���������޿�֧����ǩ����CUPNCPRawVerify����ԭ��Ϊnull
     */
    @Test(groups = "abcjew.cupncprawverify.normal")
    public void testCUPNCPRawVerify_15() {
        System.out.println("���������޿�֧����ǩ����CUPNCPRawVerify����ԭ��Ϊnull");
        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        boolean bool_result;
        String sign_text = null;
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        String alg = "SHA1";
        try {
            upkiResult = agent.CUPNCPRawSign(plainText, dn, alg);
            bool_result = upkiResult.getBoolResult();
            if (!bool_result || upkiResult.getReturnCode() != 0) {
                Assert.fail("���������޿�֧����ǩ����CUPNCPRawSign����ǩ��ʧ��" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���������޿�֧����ǩ����CUPNCPRawSign����ǩ��ʧ��" + upkiResult.getReturnCode() + upkiResult.getReturnContent() + e.getMessage());
        }

        try {
            if (upkiResult != null) {
                sign_text = upkiResult.getResults().get("sign_text").toString();
            }
            upkiResult1 = agent.CUPNCPRawVerify(null, sign_text, dn, alg);
            bool_result = upkiResult1.getBoolResult();
            if (bool_result || upkiResult1.getReturnCode() != -1026) {
                Assert.fail("���������޿�֧����ǩ����CUPNCPRawVerify������ǩ��ʧ��" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���������޿�֧����ǩ����CUPNCPRawVerify������ǩ��ʧ��" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
        }
    }

    /**
     * ���������޿�֧����ǩ����CUPNCPRawVerify����ԭ�ı��۸�
     */
    @Test(groups = "abcjew.cupncprawverify.normal")
    public void testCUPNCPRawVerify_16() {
        System.out.println("���������޿�֧����ǩ����CUPNCPRawVerify����ԭ�ı��۸�");
        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        boolean bool_result;
        String sign_text = null;
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        String alg = "SHA1";
        try {
            upkiResult = agent.CUPNCPRawSign(plainText, dn, alg);
            bool_result = upkiResult.getBoolResult();
            if (!bool_result || upkiResult.getReturnCode() != 0) {
                Assert.fail("���������޿�֧����ǩ����CUPNCPRawSign����ǩ��ʧ��" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���������޿�֧����ǩ����CUPNCPRawSign����ǩ��ʧ��" + upkiResult.getReturnCode() + upkiResult.getReturnContent() + e.getMessage());
        }

        try {
            if (upkiResult != null) {
                sign_text = upkiResult.getResults().get("sign_text").toString();
            }
            plainText = Utils.modifyData(plainText, 5, 10, "12345");
            upkiResult1 = agent.CUPNCPRawVerify(plainText, sign_text, dn, alg);
            bool_result = upkiResult1.getBoolResult();
            if (bool_result || upkiResult1.getReturnCode() != -100104) {
                Assert.fail("���������޿�֧����ǩ����CUPNCPRawVerify������ǩ��ʧ��" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail("���������޿�֧����ǩ����CUPNCPRawVerify������ǩ��ʧ��" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
        }
    }

    /**
     * ���������޿�֧����ǩ����CUPNCPRawVerify��������Ϊ�ջ�null
     */
    @Test(groups = "abcjew.cupncprawverify.normal", dataProvider = "emptys-parameter", dataProviderClass =
            NetSignDataProvider.class)
    public void testCUPNCPRawVerify_17(String sign_text) {
        System.out.println("���������޿�֧����ǩ����CUPNCPRawVerify��������Ϊ�ջ�null");
        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult1 = null;
        boolean bool_result;
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        String alg = "SHA1";
        try {
            upkiResult1 = agent.CUPNCPRawVerify(plainText, sign_text, dn, alg);
            bool_result = upkiResult1.getBoolResult();
            if (bool_result || upkiResult1.getReturnCode() != -1026) {
                Assert.fail("���������޿�֧����ǩ����CUPNCPRawVerify������ǩ��ʧ��" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            if (upkiResult1 != null) {
                Assert.fail("���������޿�֧����ǩ����CUPNCPRawSign����ǩ��ʧ��" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent() + e.getMessage());
            }
        }
    }

    /**
     * ���������޿�֧����ǩ����CUPNCPRawVerify�������ı��۸�
     */
    @Test(groups = "abcjew.cupncprawverify.normal")
    public void testCUPNCPRawVerify_18() {
        System.out.println("���������޿�֧����ǩ����CUPNCPRawVerify�������ı��۸�");
        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        boolean bool_result;
        String sign_text = null;
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        String alg = "SHA1";
        try {
            upkiResult = agent.CUPNCPRawSign(plainText, dn, alg);
            bool_result = upkiResult.getBoolResult();
            if (!bool_result || upkiResult.getReturnCode() != 0) {
                Assert.fail("���������޿�֧����ǩ����CUPNCPRawSign����ǩ��ʧ��" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            if (upkiResult != null) {
                Assert.fail("���������޿�֧����ǩ����CUPNCPRawSign����ǩ��ʧ��" + upkiResult.getReturnCode() + upkiResult.getReturnContent() + e.getMessage());
            }
        }

        try {
            if (upkiResult != null) {
                sign_text = upkiResult.getResults().get("sign_text").toString();
            }
            sign_text = Utils.modifyData(sign_text, 5, 10, "12345");
            upkiResult1 = agent.CUPNCPRawVerify(plainText, sign_text, dn, alg);
            bool_result = upkiResult1.getBoolResult();
            if (bool_result || upkiResult1.getReturnCode() != -100104) {
                Assert.fail("���������޿�֧����ǩ����CUPNCPRawVerify������ǩ��ʧ��" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            if (upkiResult1 != null) {
                Assert.fail("���������޿�֧����ǩ����CUPNCPRawSign����ǩ��ʧ��" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent() + e.getMessage());
            }
        }
    }

    /**
     * ���������޿�֧����ǩ����CUPNCPRawVerify����DNΪ�ջ�null
     */
    @Test(groups = "abcjew.cupncprawverify.normal", dataProvider = "emptys-parameter", dataProviderClass =
            NetSignDataProvider.class)
    public void testCUPNCPRawVerify_19(String dn1) {
        System.out.println("���������޿�֧����ǩ����CUPNCPRawVerify����ʹ������RSA֤��DN��ǩ");
        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        boolean bool_result;
        String sign_text = null;
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        String alg = "SHA1";
        try {
            upkiResult = agent.CUPNCPRawSign(plainText, dn, alg);
            bool_result = upkiResult.getBoolResult();
            if (!bool_result || upkiResult.getReturnCode() != 0) {
                Assert.fail("���������޿�֧����ǩ����CUPNCPRawSign����ǩ��ʧ��" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            if (upkiResult != null) {
                Assert.fail("���������޿�֧����ǩ����CUPNCPRawSign����ǩ��ʧ��" + upkiResult.getReturnCode() + upkiResult.getReturnContent() + e.getMessage());
            }
        }

        try {
            if (upkiResult != null) {
                sign_text = upkiResult.getResults().get("sign_text").toString();
            }
            upkiResult1 = agent.CUPNCPRawVerify(plainText, sign_text, dn1, alg);
            bool_result = upkiResult1.getBoolResult();
            if (bool_result || upkiResult1.getReturnCode() != -100224) {
                Assert.fail("���������޿�֧����ǩ����CUPNCPRawVerify������ǩ��ʧ��" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            if (upkiResult1 != null) {
                Assert.fail("���������޿�֧����ǩ����CUPNCPRawVerify������ǩ��ʧ��" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        }
    }

    /**
     * ���������޿�֧����ǩ����CUPNCPRawVerify������ǩDN��ǩ��DN��һ��
     *
     */
    @Test(groups = "abcjew.cupncprawverify.normal")
    public void testCUPNCPRawVerify_20() {
        System.out.println("���������޿�֧����ǩ����CUPNCPRawVerify������ǩDN��ǩ��DN��һ��");
        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        boolean bool_result;
        String sign_text = null;
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        String alg = "SHA1";
        try {
            upkiResult = agent.CUPNCPRawSign(plainText, dn, alg);
            bool_result = upkiResult.getBoolResult();
            if (!bool_result || upkiResult.getReturnCode() != 0) {
                Assert.fail("���������޿�֧����ǩ����CUPNCPRawSign����ǩ��ʧ��" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            if (upkiResult != null) {
                Assert.fail("���������޿�֧����ǩ����CUPNCPRawSign����ǩ��ʧ��" + upkiResult.getReturnCode() + upkiResult.getReturnContent() + e.getMessage());
            }
        }

        try {
            if (upkiResult != null) {
                sign_text = upkiResult.getResults().get("sign_text").toString();
            }
            upkiResult1 = agent.CUPNCPRawVerify(plainText, sign_text, "C=cn,O=INFOSEC Technologies RSA,CN=R018�Ű�����", alg);
            bool_result = upkiResult1.getBoolResult();
            if (bool_result || upkiResult1.getReturnCode() != -100104) {
                Assert.fail("���������޿�֧����ǩ����CUPNCPRawVerify������ǩ��ʧ��" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            if (upkiResult1 != null) {
                Assert.fail("���������޿�֧����ǩ����CUPNCPRawSign����ǩ��ʧ��" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent() + e.getMessage());
            }
        }
    }

    /**
     * ���������޿�֧����ǩ����CUPNCPRawVerify����ժҪ�㷨Ϊ�ջ�null
     */
    @Test(groups = "abcjew.cupncprawverify.normal", dataProvider = "emptys-parameter", dataProviderClass =
            NetSignDataProvider.class)
    public void testCUPNCPRawVerify_21(String alg1) {
        System.out.println("���������޿�֧����ǩ����CUPNCPRawVerify����ժҪ�㷨Ϊ�ջ�null");
        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        boolean bool_result;
        String sign_text = null;
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        String alg = "SHA1";
        try {
            upkiResult = agent.CUPNCPRawSign(plainText, dn, alg);
            bool_result = upkiResult.getBoolResult();
            if (!bool_result || upkiResult.getReturnCode() != 0) {
                Assert.fail("���������޿�֧����ǩ����CUPNCPRawSign����ǩ��ʧ��" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            if (upkiResult != null) {
                Assert.fail("���������޿�֧����ǩ����CUPNCPRawSign����ǩ��ʧ��" + upkiResult.getReturnCode() + upkiResult.getReturnContent() + e.getMessage());
            }
        }

        try {
            if (upkiResult != null) {
                sign_text = upkiResult.getResults().get("sign_text").toString();
            }
            upkiResult1 = agent.CUPNCPRawVerify(plainText, sign_text, dn, alg1);
            bool_result = upkiResult1.getBoolResult();
            if (bool_result || upkiResult1.getReturnCode() != -1026) {
                Assert.fail("���������޿�֧����ǩ����CUPNCPRawVerify������ǩ��ʧ��" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            if (upkiResult1 != null) {
                Assert.fail("���������޿�֧����ǩ����CUPNCPRawVerify������ǩ��ʧ��" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        }
    }

    /**
     * ���������޿�֧����ǩ����CUPNCPRawVerify������ǩժҪ�㷨��ǩ��ժҪ�㷨��һ��
     */
    @Test(groups = "abcjew.cupncprawverify.normal")
    public void testCUPNCPRawVerify_22() {
        System.out.println("���������޿�֧����ǩ����CUPNCPRawVerify������ǩժҪ�㷨��ǩ��ժҪ�㷨��һ��");
        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        boolean bool_result;
        String sign_text = null;
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        String alg = "SHA1";
        String alg1 = "SHA224";
        try {
            upkiResult = agent.CUPNCPRawSign(plainText, dn, alg);
            bool_result = upkiResult.getBoolResult();
            if (!bool_result || upkiResult.getReturnCode() != 0) {
                Assert.fail("���������޿�֧����ǩ����CUPNCPRawSign����ǩ��ʧ��" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            if (upkiResult != null) {
                Assert.fail("���������޿�֧����ǩ����CUPNCPRawSign����ǩ��ʧ��" + upkiResult.getReturnCode() + upkiResult.getReturnContent() + e.getMessage());
            }
        }

        try {
            if (upkiResult != null) {
                sign_text = upkiResult.getResults().get("sign_text").toString();
            }
            upkiResult1 = agent.CUPNCPRawVerify(plainText, sign_text, dn, alg1);
            bool_result = upkiResult1.getBoolResult();
            if (bool_result || upkiResult1.getReturnCode() != -100104) {
                Assert.fail("���������޿�֧����ǩ����CUPNCPRawVerify������ǩ��ʧ��" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            if (upkiResult1 != null) {
                Assert.fail("���������޿�֧����ǩ����CUPNCPRawVerify������ǩ��ʧ��" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        }
    }

    /**
     * ���������޿�֧����ǩ����CUPNCPRawVerify����ժҪ�㷨����
     */
    @Test(groups = "abcjew.cupncprawverify.normal")
    public void testCUPNCPRawVerify_23() {
        System.out.println("���������޿�֧����ǩ����CUPNCPRawVerify����ժҪ�㷨����");
        byte[] plainText = Utils.getRandomString(64).getBytes();
        UpkiResult upkiResult = null;
        UpkiResult upkiResult1 = null;
        boolean bool_result;
        String sign_text = null;
        String dn = "C=cn,O=INFOSEC Technologies RSA,CN=R018normal";
        String alg = "SHA1";
        String alg1 = "SHA3";
        try {
            upkiResult = agent.CUPNCPRawSign(plainText, dn, alg);
            bool_result = upkiResult.getBoolResult();
            if (!bool_result || upkiResult.getReturnCode() != 0) {
                Assert.fail("���������޿�֧����ǩ����CUPNCPRawSign����ǩ��ʧ��" + upkiResult.getReturnCode() + upkiResult.getReturnContent());
            }
        } catch (Exception e) {
            if (upkiResult != null) {
                Assert.fail("���������޿�֧����ǩ����CUPNCPRawSign����ǩ��ʧ��" + upkiResult.getReturnCode() + upkiResult.getReturnContent() + e.getMessage());
            }
        }

        try {
            if (upkiResult != null) {
                sign_text = upkiResult.getResults().get("sign_text").toString();
            }
            upkiResult1 = agent.CUPNCPRawVerify(plainText, sign_text, dn, alg1);
            bool_result = upkiResult1.getBoolResult();
            if (bool_result || upkiResult1.getReturnCode() != -100112) {
                Assert.fail("���������޿�֧����ǩ����CUPNCPRawVerify������ǩ��ʧ��" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        } catch (Exception e) {
            if (upkiResult1 != null) {
                Assert.fail("���������޿�֧����ǩ����CUPNCPRawVerify������ǩ��ʧ��" + upkiResult1.getReturnCode() + upkiResult1.getReturnContent());
            }
        }
    }
}
