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
import java.util.Random;

/**
 * @author suiyixin
 * @ClassName: TestRawVerify
 * @date 2020-03-05 9:40
 * @Description: <p>�������ǵ㣺</p>
 * <p>1��sPublickey��Կ֤��Ϊnull��������������ȷ</p>
 * <p>2��sPublickey��Կ֤��Ϊ���ַ�����������������ȷ</p>
 * <p>3��pOrgDataԭ�Ĳ�һ��</p>
 * <p>4��pOrgDataԭ��Ϊnull</p>
 * <p>5��pOrgDataԭ��Ϊ��</p>
 * <p>6��pOrgData��ԭ��</p>
 * <p>7��sCertDN��Կ��֤���������</p>
 * <p>8��sCertDN��Կ������</p>
 * <p>9��sCertDN��Կ��ǩ����һ��</p>
 * <p>10��sCertDNΪnull��sPublickey��Կ֤����ȷ</p>
 * <p>11��sCertDNΪ���ַ�����sPublickey��Կ֤����ȷ</p>
 * <p>12������֤��DN</p>
 * <p>13������֤��DN</p>
 * <p>14����������֤��DN</p>
 * <p>15��������֤��DN</p>
 * <p>16��sDigestAlgժҪ�㷨Ϊ��</p>
 * <p>17��sDigestAlgժҪ�㷨Ϊnull</p>
 * <p>18��sDigestAlgժҪ�㷨������</p>
 * <p>19��sDigestAlgժҪ�㷨��ǩ����һ��</p>
 * <p>20��sDigestAlgժҪ�㷨Сд</p>
 * <p>21��pSignDataǩ��ֵ���۸�</p>
 * <p>22��pSignDataǩ��ֵΪ�ջ���null</p>
 * <p>23��sPublickey��Կ֤����ǩ����һ��</p>
 * <p>24��sCertDN��sPublickey��Ϊ��/null</p>
 * <p>25��sCertDN��sPublickey�����룬ʹ��sPublickey</p>
 */
public class TestRawVerify {
    static String ip, port, password;
    static String host, sftp_port, sftp_password, sftp_user;
    Random random = new Random();

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
     * ���飬��Կ֤��Ϊnull��������������ȷ
     */
    @Test(groups = "abcjew.rawverify.normal", dataProvider = "normal-alg-dn", dataProviderClass =
            NetSignDataProvider.class)
    public void testrawVerify_01(String alg, String dn) {
        System.out.println("����(rawVerify),��������ȷ����Կ֤��Ϊnull��DN");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult sign;
            UpkiResult verify;
            sign = agent.rawSign(pOrgData, dn, alg);
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            String signresult = sign_text.toString();
            verify = agent.rawVerify(pOrgData, dn, alg, signresult, null);
            if (verify.getBoolResult() != true || verify.getReturnCode() != 0
                    || !"success".equals(verify.getReturnContent())) {
                Assert.fail(" ��E��ABCJEW���飬���Թ�Կ֤��Ϊ��ʹ��DN��ʧ�ܣ�" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" ��E��ABCJEW���飬���Թ�Կ֤��Ϊ��ʹ��DN�����쳣��" + e.getMessage());
        }
    }

    /**
     * ���飬��Կ֤��Ϊ���ַ�����������������ȷ
     */
    @Test(groups = "abcjew.rawverify.normal", dataProvider = "normal-alg-dn", dataProviderClass =
            NetSignDataProvider.class)
    public void testrawVerify_02(String alg, String dn) {
        System.out.println("����(rawVerify),��������ȷ����Կ֤��Ϊ�մ�DN");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult sign;
            UpkiResult verify;
            sign = agent.rawSign(pOrgData, dn, alg);
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            String signresult = sign_text.toString();
            verify = agent.rawVerify(pOrgData, dn, alg, signresult, "");
            if (verify.getBoolResult() != true || verify.getReturnCode() != 0
                    || !"success".equals(verify.getReturnContent())) {
                Assert.fail(" ��E��ABCJEW���飬���Թ�Կ֤��Ϊnullʹ��DN��ʧ�ܣ�" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" ��E��ABCJEW���飬���Թ�Կ֤��Ϊnullʹ��DN�����쳣��" + e.getMessage());
        }
    }

    /**
     * ���飬ԭ�Ĳ�һ��
     */
    @Test(groups = "abcjew.rawverify.normal", dataProvider = "normal-alg-dn", dataProviderClass =
            NetSignDataProvider.class)
    public void testrawVerify_03(String alg, String dn) {
        System.out.println("����(rawVerify),ԭ�Ĳ�һ��");
        try {
            UpkiResult sign;
            UpkiResult verify;
            sign = agent.rawSign("aaa".getBytes(), dn, alg);
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            String signresult = sign_text.toString();

            verify = agent.rawVerify("basdd".getBytes(), dn, alg, signresult, null);
            if (verify.getReturnCode() != -100104) {
                Assert.fail(" ��E��ABCJEW���飬����ԭ�Ĳ�һ�£�ʧ�ܣ�" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" ��E��ABCJEW���飬����ԭ�Ĳ�һ�£����쳣��" + e.getMessage());
        }
    }

    /**
     * ���飬ԭ��Ϊnull
     */
    @Test(groups = "abcjew.rawverify.normal", dataProvider = "normal-alg-dn", dataProviderClass =
            NetSignDataProvider.class)
    public void testrawVerify_04(String alg, String dn) {
        System.out.println("����(rawVerify),ԭ��Ϊnull");
        try {
            UpkiResult sign;
            UpkiResult verify;
            sign = agent.rawSign("".getBytes(), dn, alg);
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            String signresult = sign_text.toString();

            verify = agent.rawVerify(null, dn, alg, signresult, null);
            if (verify.getReturnCode() != -1027) {
                Assert.fail(" ��E��ABCJEW���飬����ԭ��Ϊnull��ʧ�ܣ�" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" ��E��ABCJEW���飬����ԭ��Ϊnull�����쳣��" + e.getMessage());
        }
    }

    /**
     * ���飬ԭ��Ϊ��
     */
    @Test(groups = "abcjew.rawverify.normal", dataProvider = "normal-alg-dn", dataProviderClass =
            NetSignDataProvider.class)
    public void testrawVerify_05(String alg, String dn) {
        System.out.println("����(rawVerify),ԭ��Ϊ��");
        try {
            UpkiResult sign;
            UpkiResult verify;
            sign = agent.rawSign("".getBytes(), dn, alg);
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            String signresult = sign_text.toString();

            verify = agent.rawVerify("".getBytes(), dn, alg, signresult, null);
            boolean code = verify.getBoolResult();
            if (verify.getReturnCode() != -1027) {
                if (verify.getReturnCode() != 0) {
                    Assert.fail(" ��E��ABCJEW���飬����ԭ��Ϊ�գ�ʧ�ܣ�" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
                }
                Reporter.log("��E��ABCJEW���飬ԭ�Ĵ����ַ�������ǩ�ɹ�");
            }

        } catch (Exception e) {
            Assert.fail(" ��E��ABCJEW���飬����ԭ��Ϊ�գ����쳣��" + e.getMessage());
        }
    }

    /**
     * ���飬sCertDN��֤���������
     */
    @Test(groups = "abcjew.rawverify.normal", dataProvider = "normal-alg-bankcode", dataProviderClass =
            NetSignDataProvider.class)
    public void testrawVerify_06(String alg, String bankcode) {
        System.out.println("����(rawVerify),sCertDN��֤���������");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult sign;
            UpkiResult verify;
            sign = agent.rawSign(pOrgData, bankcode, alg);
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            String signresult = sign_text.toString();

            verify = agent.rawVerify(pOrgData, bankcode, alg, signresult, null);
            if (verify.getBoolResult() != true || verify.getReturnCode() != 0
                    || !"success".equals(verify.getReturnContent())) {
                Assert.fail(" ��E��ABCJEW���飬���Դ���Կ֤��������룬ʧ�ܣ�" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" ��E��ABCJEW���飬���Դ���Կ֤��������룬���쳣��" + e.getMessage());
        }
    }

    /**
     * ���飬�������ڵ���Կ
     */
    @Test(groups = "abcjew.rawverify.normal")
    public void testrawVerify_07() {
        System.out.println("����(rawVerify),�������ڵ���Կ");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult sign;
            UpkiResult verify;
            sign = agent.rawSign(pOrgData, "C=cn,O=INFOSEC Technologies RSA,CN=SS019normal", "SHA256");
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            String signresult = sign_text.toString();
            verify = agent.rawVerify(pOrgData, "bucunzaidemiyue", "SHA256", signresult, null);
            if (verify.getBoolResult() != false || verify.getReturnCode() != -100224) {
                Assert.fail(" ��E��ABCJEW���飬���Դ������ڵ���Կ��ʧ�ܣ�" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" ��E��ABCJEW���飬���Դ������ڵ���Կ�����쳣��" + e.getMessage());
        }
    }

    /**
     * ���飬����ǩ����һ�µ���Կ
     */
    @Test(groups = "abcjew.rawverify.normal")
    public void testrawVerify_08() {
        System.out.println("����(rawVerify),����ǩ��ʱ��һ�µ���Կ");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult sign;
            UpkiResult verify;
            sign = agent.rawSign(pOrgData, "C=cn,O=INFOSEC Technologies RSA,CN=SS019normal", "SHA256");
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            String signresult = sign_text.toString();
            verify = agent.rawVerify(pOrgData, "C=cn,O=INFOSEC Technologies RSA,CN=S019Դ�������ڰ�", "SHA256", signresult,
                    null);
            if (verify.getBoolResult() != false || verify.getReturnCode() != -100104) {
                Assert.fail(" ��E��ABCJEW���飬���Դ���ǩ����һ�µ���Կ��ʧ�ܣ�" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" ��E��ABCJEW���飬���Դ���ǩ����һ�µ���Կ�����쳣��" + e.getMessage());
        }
    }

    /**
     * ���飬DNΪnull��ʹ����ȷ��sPublickey��Կ֤��
     */
    @Test(groups = "abcjew.rawverify.normal", dataProvider = "normal-alg-dn-cert", dataProviderClass =
            NetSignDataProvider.class)
    public void testrawVerify_09(String alg, String dn, String cert) {
        System.out.println("����(rawVerify),DNΪnull����Կ֤��");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult sign;
            UpkiResult verify;
            sign = agent.rawSign(pOrgData, dn, alg);
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            String signresult = sign_text.toString();
            verify = agent.rawVerify(pOrgData, null, alg, signresult, cert);

            if (verify.getBoolResult() != true || verify.getReturnCode() != 0
                    || !"success".equals(verify.getReturnContent())) {
                Assert.fail(" ��E��ABCJEW���飬����DNΪnull����Կ֤�飬ʧ�ܣ�" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" ��E��ABCJEW���飬����DNΪnull����Կ֤�飬���쳣��" + e.getMessage());
        }
    }

    /**
     * ���飬DNΪ���ַ�����ʹ����ȷ��sPublickey��Կ֤��
     */
    @Test(groups = "abcjew.rawverify.normal", dataProvider = "normal-alg-dn-cert", dataProviderClass =
            NetSignDataProvider.class)
    public void testrawVerify_10(String alg, String dn, String cert) {
        System.out.println("����(rawVerify),DNΪ�մ���Կ֤��");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult sign;
            UpkiResult verify;
            sign = agent.rawSign(pOrgData, dn, alg);
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            String signresult = sign_text.toString();
            verify = agent.rawVerify(pOrgData, "", alg, signresult, cert);

            if (verify.getBoolResult() != true || verify.getReturnCode() != 0
                    || !"success".equals(verify.getReturnContent())) {
                Assert.fail(" ��E��ABCJEW���飬����DNΪ���ַ�������Կ֤�飬ʧ�ܣ�" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" ��E��ABCJEW���飬����DNΪ���ַ�������Կ֤�飬���쳣��" + e.getMessage());
        }
    }

    /**
     * ���飬����֤��
     */
    @Test(groups = "abcjew.rawverify.normal", dataProvider = "expire-alg-dn", dataProviderClass =
            NetSignDataProvider.class)
    public void testrawVerify_11(String alg, String dn) {
        System.out.println("����(rawVerify),֤�����");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult sign;
            UpkiResult verify;
            sign = agent.rawSign(pOrgData, dn, alg);
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            String signresult = sign_text.toString();
            verify = agent.rawVerify(pOrgData, dn, alg, signresult, null);
            if (verify.getBoolResult() != false || verify.getReturnCode() != -100106) {
                Assert.fail(" ��E��ABCJEW���飬���Թ���֤�飬ʧ�ܣ�" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" ��E��ABCJEW���飬���Թ���֤�飬���쳣��" + e.getMessage());
        }
    }

    /**
     * ���飬����֤��
     */
    @Test(groups = "abcjew.rawverify.normal", dataProvider = "revoke-alg-dn", dataProviderClass =
            NetSignDataProvider.class)
    public void testrawVerify_12(String alg, String dn) {
        System.out.println("����(rawVerify),֤������");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult sign;
            UpkiResult verify;
            sign = agent.rawSign(pOrgData, dn, alg);
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            String signresult = sign_text.toString();
            if (!("C=CN,O=infosec,OU=test3,CN=C020revokeMatchingAnyCrlfbd").equals(dn)
                    && !("C=CN,O=infosec,CN=C020revokedNocrlfile").equals(dn)) {
                verify = agent.rawVerify(pOrgData, dn, alg, signresult, null);
                if (verify.getBoolResult() != false || verify.getReturnCode() != -100108) {
                    Assert.fail(" ��E��ABCJEW���飬��������֤�飬ʧ�ܣ�" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
                }
            }
        } catch (Exception e) {
            Assert.fail(" ��E��ABCJEW���飬��������֤�飬���쳣��" + e.getMessage());
        }

    }

    /**
     * ���飬��������֤��
     */
    @Test(groups = "abcjew.rawverify.normal", dataProvider = "nottrust-alg-dn", dataProviderClass =
            NetSignDataProvider.class)
    public void testrawVerify_13(String alg, String dn) {
        System.out.println("����(rawVerify),֤�鲻������");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult sign;
            UpkiResult verify;
            sign = agent.rawSign(pOrgData, dn, alg);
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            String signresult = sign_text.toString();
            verify = agent.rawVerify(pOrgData, dn, alg, signresult, null);
            if (verify.getBoolResult() != false || verify.getReturnCode() != -100124) {
                Assert.fail(" ��E��ABCJEW���飬���Բ�������֤�飬ʧ�ܣ�" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" ��E��ABCJEW���飬���Բ�������֤�飬���쳣��" + e.getMessage());
        }
    }

    /**
     * ���飬������֤��
     */
    @Test(groups = "abcjew.rawverify.normal", dataProvider = "blacklist-alg-dn", dataProviderClass =
            NetSignDataProvider.class)
    public void testrawVerify_14(String alg, String dn) {
        System.out.println("����(rawVerify),֤�鴦�ں�����");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult sign;
            UpkiResult verify;
            sign = agent.rawSign(pOrgData, dn, alg);
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            String signresult = sign_text.toString();
            verify = agent.rawVerify(pOrgData, dn, alg, signresult, null);
            if (verify.getBoolResult() != false || verify.getReturnCode() != -100226) {
                Assert.fail(" ��E��ABCJEW���飬���Ժ�����֤�飬ʧ�ܣ�" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" ��E��ABCJEW���飬���Ժ�����֤�飬���쳣��" + e.getMessage());
        }
    }

    /**
     * ���飬AlgΪ��
     */
    @Test(groups = "abcjew.rawverify.normal", dataProvider = "normal-dn", dataProviderClass = NetSignDataProvider.class)
    public void testrawVerify_15(String dn) {
        System.out.println("����(rawVerify),ժҪ�㷨AlgΪ��");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult sign;
            UpkiResult verify;
            sign = agent.rawSign(pOrgData, dn, "");
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            String signresult = sign_text.toString();
            verify = agent.rawVerify(pOrgData, dn, "", signresult, null);
            if (verify.getBoolResult() != true || verify.getReturnCode() != 0
                    || !"success".equals(verify.getReturnContent())) {
                Assert.fail(" ��E��ABCJEW���飬����ժҪ�㷨Ϊ�գ�ʧ�ܣ�" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" ��E��ABCJEW������ժҪ�㷨Ϊ�գ����쳣��" + e.getMessage());
        }
    }

    /**
     * ���飬AlgΪnull
     */
    @Test(groups = "abcjew.rawverify.normal", dataProvider = "normal-dn", dataProviderClass = NetSignDataProvider.class)
    public void testrawVerify_16(String dn) {
        System.out.println("����(rawVerify),ժҪ�㷨AlgΪnull");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult sign;
            UpkiResult verify;
            sign = agent.rawSign(pOrgData, dn, null);
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            String signresult = sign_text.toString();
            verify = agent.rawVerify(pOrgData, dn, null, signresult, null);
            if (verify.getBoolResult() != true || verify.getReturnCode() != 0
                    || !"success".equals(verify.getReturnContent())) {
                Assert.fail(" ��E��ABCJEW���飬����ժҪ�㷨Ϊnull��ʧ�ܣ�" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" ��E��ABCJEW���飬����ժҪ�㷨Ϊnull�����쳣��" + e.getMessage());
        }
    }

    /**
     * ���飬Alg������
     */
    @Test(groups = "abcjew.rawverify.normal")
    public void testrawVerify_17() {
        System.out.println("����(rawVerify),ժҪ�㷨Alg������");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult sign;
            UpkiResult verify;
            sign = agent.rawSign(pOrgData, "C=cn,O=INFOSEC Technologies RSA,CN=R018normal", "SHA1");
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            String signresult = sign_text.toString();
            verify = agent.rawVerify(pOrgData, "C=cn,O=INFOSEC Technologies RSA,CN=R018normal", "sss", signresult,
                    null);
            if (verify.getBoolResult() != false || verify.getReturnCode() != -100112) {
                Assert.fail(" ��E��ABCJEW���飬���Բ����ڵ�ժҪ�㷨��ʧ�ܣ�" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" ��E��ABCJEW���飬���Բ����ڵ�ժҪ�㷨�����쳣��" + e.getMessage());
        }
    }

    /**
     * ���飬Alg��ǩ����һ��
     */
    @Test(groups = "abcjew.rawverify.normal", dataProvider = "normal-dn", dataProviderClass = NetSignDataProvider.class)
    public void testrawVerify_18(String dn) {
        System.out.println("����(rawVerify),ժҪ�㷨Alg��ǩ����һ��");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult sign;
            UpkiResult verify;
            sign = agent.rawSign(pOrgData, dn, "SHA1");
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            String signresult = sign_text.toString();
            verify = agent.rawVerify(pOrgData, dn, "SHA256", signresult, null);
            if (verify.getBoolResult() != false || verify.getReturnCode() != -100104) {
                Assert.fail(" ��E��ABCJEW���飬������ǩ��ʱ��һ�µ�ժҪ�㷨��ʧ�ܣ�" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" ��E��ABCJEW���飬������ǩ��ʱ��һ�µ�ժҪ�㷨�����쳣��" + e.getMessage());
        }
    }

    /**
     * ���飬AlgСд
     */
    @Test(groups = "abcjew.rawverify.normal", dataProvider = "normal-alg-dn", dataProviderClass =
            NetSignDataProvider.class)
    public void testrawVerify_19(String alg, String dn) {
        System.out.println("����(rawVerify),ժҪ�㷨AlgСд");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult sign;
            UpkiResult verify;
            String littlealg = alg.toLowerCase();
            sign = agent.rawSign(pOrgData, dn, littlealg);
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            String signresult = sign_text.toString();
            verify = agent.rawVerify(pOrgData, dn, littlealg, signresult, null);
            if (verify.getBoolResult() != true || verify.getReturnCode() != 0) {
                if (verify.getReturnCode() != -100112) {
                    Assert.fail(" ��E��ABCJEW���飬����СдժҪ�㷨��ʧ�ܣ�" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
                }
                Reporter.log("��E��ABCJEW���飬СдժҪ�㷨����ǩʧ�ܣ���֧��Сд");
            }
        } catch (Exception e) {
            Assert.fail(" ��E��ABCJEW���飬����СдժҪ�㷨�����쳣��" + e.getMessage());
        }
    }

    /**
     * ���飬ǩ��ֵ���۸�
     */
    @Test(groups = "abcjew.rawverify.normal", dataProvider = "normal-alg-dn", dataProviderClass =
            NetSignDataProvider.class)
    public void testrawVerify_20(String alg, String dn) {
        System.out.println("����(rawVerify),ǩ��ֵ���۸�");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult sign;
            UpkiResult verify;
            String new_sign_result = "";
            sign = agent.rawSign(pOrgData, dn, alg);
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            String sign_result = sign_text.toString();
            // �޸�ǩ�����
            StringBuilder sb = new StringBuilder(sign_result);
            sb.replace(8, 10, "2a");
            new_sign_result = sb.toString();
            verify = agent.rawVerify(pOrgData, dn, alg, new_sign_result, null);
            if (verify.getBoolResult() != false || verify.getReturnCode() != -100104) {
                Assert.fail(" ��E��ABCJEW���飬���Ա��۸ĵ�ǩ��ֵ��ʧ�ܣ�" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" ��E��ABCJEW���飬���Ա��۸ĵ�ǩ��ֵ�����쳣��" + e.getMessage());
        }
    }

    /**
     * ���飬ǩ��ֵΪ�ջ���null
     */
    @Test(groups = "abcjew.rawverify.normal", dataProvider = "emptys-parameter", dataProviderClass =
            NetSignDataProvider.class)
    public void testrawVerify_21(String sign) {
        System.out.println("����(rawVerify),ǩ��ֵΪ�ջ�null");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult verify;
            verify = agent.rawVerify(pOrgData, "C=cn,O=INFOSEC Technologies RSA,CN=R018normal", "SHA256", sign, null);
            if (verify.getReturnCode() != -1027) {
                if (verify.getReturnCode() != -100104) {
                    Assert.fail(" ��E��ABCJEW���飬����ǩ��ֵΪ�ջ���null��ʧ�ܣ�" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
                }
            }
        } catch (Exception e) {
            Assert.fail(" ��E��ABCJEW���飬����ǩ��ֵΪ�ջ���null�����쳣��" + e.getMessage());
        }
    }

    /**
     * ���飬��Կ֤����ǩ��ֵ��һ��
     */
    @Test(groups = "abcjew.rawverify.normal")
    public void testrawVerify_22() {
        System.out.println("����(rawVerify),��Կ֤����ǩ��ֵ��һ��");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult sign;
            UpkiResult verify;
            sign = agent.rawSign(pOrgData, "C=cn,O=INFOSEC Technologies RSA,CN=SS019normal", "SHA256");
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            String signresult = sign_text.toString();
            String sPublickey = "MIICUzCCAfagAwIBAgIGALceda" +
                    "+AMAwGCCqBHM9VAYN1BQAwUTELMAkGA1UEBhMCY24xKTAnBgNVBAoMIElORk9TRUMgVGVjaG5vbG9naWVzIFNNMklEX1NVQkNBMRcwFQYDVQQDDA5hcHBTTTJJRF9TVUJDQTAeFw0xODA1MDMwNTUzNDBaFw0yNjA0MTkwNzE2NTBaMEMxCzAJBgNVBAYTAmNuMSEwHwYDVQQKDBhJTkZPU0VDIFRlY2hub2xvZ2llcyBSU0ExETAPBgNVBAMMCFMwMTlfIyEkMFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAErFvPNyY3l93bHRyFpwptEV0cEvR/QjrkGma1DRjcY6beWW5wmlrcoBKYW3h2RALrP+r4nfroRSD7yIpjveS/4aOBxTCBwjAfBgNVHSMEGDAWgBRQlLwbc3s6aiWtLrw91rqo+4hB9DAJBgNVHRMEAjAAMGgGA1UdHwRhMF8wXaBboFmkVzBVMQ0wCwYDVQQDDARjcmwzMQwwCgYDVQQLDANjcmwxKTAnBgNVBAoMIElORk9TRUMgVGVjaG5vbG9naWVzIFNNMklEX1NVQkNBMQswCQYDVQQGEwJjbjALBgNVHQ8EBAMCB4AwHQYDVR0OBBYEFH2gnd6tjMZLI6gYoSHEq8Lc5zt8MAwGCCqBHM9VAYN1BQADSQAwRgIhAOhonE4h5W9BGPwEFqwwDpv+0XgydohmzTupwRGGQcdvAiEA2EnJZ3+6UUDxzZX6mxiXDnS5M32v6wf29u3B/YjoPNg=";
            verify = agent.rawVerify(pOrgData, null, "SHA256", signresult, sPublickey);
            if (verify.getBoolResult() != false || verify.getReturnCode() != -100104) {
                Assert.fail(" ��E��ABCJEW���飬���Թ�Կ֤����ǩ��ֵ��һ�£�ʧ�ܣ�" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" ��E��ABCJEW���飬���Թ�Կ֤����ǩ��ֵ��һ�£����쳣��" + e.getMessage());
        }
    }

    /**
     * ���飬DN�͹�Կ֤���Ϊ��/null
     */
    @Test(groups = "abcjew.rawverify.normal", dataProvider = "emptys-parameter", dataProviderClass =
            NetSignDataProvider.class)
    public void testrawVerify_23(String cert) {
        System.out.println("����(rawVerify),DN�͹�Կ֤���Ϊ��/null");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult sign;
            UpkiResult verify;
            sign = agent.rawSign(pOrgData, "C=cn,O=INFOSEC Technologies RSA,CN=SS019normal", "SHA256");
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            String signresult = sign_text.toString();
            verify = agent.rawVerify(pOrgData, cert, "SHA256", signresult, cert);
            if (verify.getBoolResult() != false || verify.getReturnCode() != -100224) {
                Assert.fail(" ��E��ABCJEW���飬����DN�͹�Կ֤�鴫�ջ�null��ʧ�ܣ�" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" ��E��ABCJEW���飬����DN�͹�Կ֤�鴫�ջ�null�����쳣��" + e.getMessage());
        }
    }

    /**
     * ���飬DN�͹�Կ֤������룬ʹ����ȷ��sPublickey��Կ֤��
     */
    @Test(groups = "abcjew.rawverify.normal", dataProvider = "normal-alg-dn-cert", dataProviderClass =
            NetSignDataProvider.class)
    public void testrawVerify_24(String alg, String dn, String cert) {
        System.out.println("����(rawVerify),DN�͹�Կ֤������룬ʹ����ȷ��sPublickey��Կ֤��");
        byte[] pOrgData = Utils.getRandomString(64).getBytes();
        try {
            UpkiResult sign;
            UpkiResult verify;
            sign = agent.rawSign(pOrgData, dn, alg);
            Map result = sign.getResults();
            Object sign_text = result.get("sign_text");
            String signresult = sign_text.toString();
            verify = agent.rawVerify(pOrgData, "CN=bucunzaidemiyue", alg, signresult, cert);

            if (verify.getBoolResult() != true || verify.getReturnCode() != 0
                    || !"success".equals(verify.getReturnContent())) {
                Assert.fail(" ��E��ABCJEW���飬����DN�͹�Կ֤��������Ƿ�ʹ�ù�Կ֤�飬ʧ�ܣ�" + verify.getBoolResult() + verify.getReturnCode() + verify.getReturnContent());
            }
        } catch (Exception e) {
            Assert.fail(" ��E��ABCJEW����,����DN�͹�Կ֤��������Ƿ�ʹ�ù�Կ֤�飬���쳣��" + e.getMessage());
        }
    }
}
