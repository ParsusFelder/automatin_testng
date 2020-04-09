package qa.infosec.testng.netsign.dataprovider.util;

import cn.com.infosec.jce.provider.InfosecProvider;
import cn.com.infosec.util.Base64;
import org.testng.Assert;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * 解析证书
 * <p>Title: ParseCert</p>
 * <p>Description: </p>
 *
 * @author maxf
 * @date 2019年8月13日
 */
public class ParseCert {

    static {
        Security.addProvider(new InfosecProvider());
    }

    /**
     * 解析证书
     *
     * @param certpath 证书路径
     * @param keyType  证书类型，当为null时，返回所有证书
     * @return X509Certificate[]
     */
    public static ArrayList<X509Certificate> getCert(String certpath, String keyType) {

        File dir = new File(certpath);
        File[] f = dir.listFiles();

        String algoid = "";
        ArrayList<X509Certificate> certlist = new ArrayList<X509Certificate>();
        if (null == f || f.length == 0) {
            Assert.fail(certpath + "目录为空，无法读取证书");
        } else {
            try {
                for (int i = 0; i < f.length; i++) {
                    CertificateFactory certFactory = CertificateFactory.getInstance("X.509", "INFOSEC");
                    FileInputStream fis = new FileInputStream(f[i]);
                    X509Certificate cert = (X509Certificate) certFactory.generateCertificate(fis);
                    fis.close();
                    algoid = cert.getSigAlgOID();

                    if (keyType == null || keyType.toLowerCase().equals("all")) {
                        certlist.add(cert);
                        continue;
                    }

                    if ("1.2.156.10197.1.501".equals(algoid)) {    // SM2
                        if (keyType.toLowerCase().equals("sm2")) {
                            certlist.add(cert);
                        }
                    } else {
                        if (keyType.toLowerCase().equals("rsa")) {
                            certlist.add(cert);
                        }
                    }
                }
            } catch (Exception e) {
                e.getStackTrace();
            }
        }
        return certlist;
    }

    public static String[] getCertPubkey(String certpath, String keyType) throws IOException {
        String subjectPubkey = "";
        byte[] pubkey = null;
        List<String> pubList = new ArrayList<>();
        X509Certificate[] cert = (X509Certificate[]) getCert(certpath, keyType)
                .toArray(new X509Certificate[0]);

        for (int i = 0; i < cert.length; i++) {
            pubkey = cert[i].getPublicKey().getEncoded();
            subjectPubkey = Base64.encode(pubkey);
            pubList.add(subjectPubkey);
        }
        return pubList.toArray(new String[pubList.size()]);
    }

    public static String[] parseCertByAttributes(String attr, String certpath, String keyType) {
        String str = null;
        List<String> lists = new ArrayList<String>();
        X509Certificate[] cert = (X509Certificate[]) getCert(certpath, keyType)
                .toArray(new X509Certificate[0]);
        if (attr != null && attr.length() != 0) {
            if (attr.toLowerCase().equals("dn")) {
                for (int i = 0; i < cert.length; i++) {
                    str = cert[i].getSubjectDN().getName();
                    lists.add(str);
                }
            } else if (attr.toLowerCase().equals("sn")) {
                for (int i = 0; i < cert.length; i++) {
                    str = Utils.biginter2HexString(cert[i].getSerialNumber());
                    lists.add(str);
                }
            } else if (attr.toLowerCase().equals("bankcode")) {
                String[] bankCode = ParseFile.getBankCode(ParameterUtil.localdetailpath, certpath, keyType);
                for (int i = 0; i < bankCode.length; i++) {
                    lists.add(bankCode[i]);
                }
            } else {
                return null;
            }
        }
        return lists.toArray(new String[lists.size()]);
    }

    /**
     * X509Certificate 类型证书转换为base64格式
     *
     * @param certificate
     * @return base64Cert
     */
    public static String getBase64Cert(X509Certificate certificate) {
        String base64Cert = null;
        if (certificate != null) {
            try {
                base64Cert = cn.com.infosec.util.Base64.encode(certificate.getEncoded());
            } catch (CertificateEncodingException | IOException e) {
                e.printStackTrace();
            }
        }
        return base64Cert;
    }


    public static void main(String[] args) {
        String[] strings = parseCertByAttributes(null, ParameterUtil.allcertpath, "sm2");
        for (int i = 0; i < strings.length; i++) {
            System.out.println(strings[i]);
        }
    }

}
