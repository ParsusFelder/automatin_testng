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
import java.util.Arrays;
import java.util.List;

/**
 * 解析证书
 * <p>Title: ParseCert</p>
 * <p>Description: </p>
 *
 * @author zhaoyongzhi
 * @date 2020年4月26日
 */
public class ParseCert {

    static {
        Security.addProvider(new InfosecProvider());
    }

    /**
     * 解析证书
     *
     * @param certpath 证书路径
     * @param keyType  证书类型，当为all时，返回所有证书
     * @return X509Certificate[]
     */
    public static ArrayList<X509Certificate> getCert(String certpath, String keyType) {

        File dir = new File(certpath);
        File[] f = dir.listFiles();

        String algoid;
        ArrayList<X509Certificate> certlist = new ArrayList<>();
        if (null == f || f.length == 0) {
            Assert.fail(certpath + "目录为空，无法读取证书");
        } else {
            try {
                for (File file : f) {
                    CertificateFactory certFactory = CertificateFactory.getInstance("X.509", "INFOSEC");
                    FileInputStream fis = new FileInputStream(file);
                    X509Certificate cert = (X509Certificate) certFactory.generateCertificate(fis);
                    fis.close();
                    algoid = cert.getSigAlgOID();

                    if (keyType == null || "all".equals(keyType.toLowerCase())) {
                        certlist.add(cert);
                        continue;
                    }

                    if ("1.2.156.10197.1.501".equals(algoid)) {
                        if ("sm2".equals(keyType.toLowerCase())) {
                            certlist.add(cert);
                        }
                    } else {
                        if ("rsa".equals(keyType.toLowerCase())) {
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
        String subjectPubkey;
        byte[] pubkey;
        List<String> pubList = new ArrayList<>();
        X509Certificate[] cert = getCert(certpath, keyType)
                .toArray(new X509Certificate[0]);

        for (X509Certificate x509Certificate : cert) {
            pubkey = x509Certificate.getPublicKey().getEncoded();
            subjectPubkey = Base64.encode(pubkey);
            pubList.add(subjectPubkey);
        }
        return pubList.toArray(new String[0]);
    }

    public static String[] parseCertByAttributes(String attr, String certpath, String keyType) {
        String str;
        List<String> lists = new ArrayList<>();
        X509Certificate[] cert = getCert(certpath, keyType)
                .toArray(new X509Certificate[0]);
        if (attr != null && attr.length() != 0) {
            switch (attr.toLowerCase()) {
                case "dn":
                    for (X509Certificate x509Certificate : cert) {
                        str = x509Certificate.getSubjectDN().getName();
                        lists.add(str);
                    }
                    break;
                case "sn":
                    for (X509Certificate x509Certificate : cert) {
                        str = Utils.biginter2HexString(x509Certificate.getSerialNumber());
                        lists.add(str);
                    }
                    break;
                case "bankcode":
                    String[] bankCode = ParseFile.getBankCode(ParameterUtil.localdetailpath, certpath, keyType);
                    lists.addAll(Arrays.asList(bankCode));
                    break;
                default:
                    return null;
            }
        }
        return lists.toArray(new String[0]);
    }

    /**
     * X509Certificate 类型证书转换为base64格式
     *
     * @param certificate 证书内容
     * @return base64Cert 证书的base64信息
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
        String[] strings = parseCertByAttributes("bankcode", ParameterUtil.normalpath, "all");
        for (String string : strings) {
            System.out.println(string);
        }
    }

}
