import java.io.InputStream;
import java.io.ObjectInputFilter;
import java.io.ObjectInputStream;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.SAXParserFactory;
import javax.xml.stream.XMLInputFactory;

class InputValidationTests {

    Object deserialize(InputStream in) throws Exception {
        // ruleid: traust-java-input-validation-untrusted-deserialization
        ObjectInputStream ois = new ObjectInputStream(in);
        // ruleid: traust-java-input-validation-untrusted-deserialization
        return ois.readObject();
    }

    Object deserializeFiltered(InputStream in) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(in);
        ois.setObjectInputFilter(ObjectInputFilter.Config.createFilter("com.example.*;!*"));
        // ok: traust-java-input-validation-untrusted-deserialization
        return ois.readObject();
    }

    void xmlUnhardened() throws Exception {
        // ruleid: traust-java-input-validation-xxe-factory
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        // ruleid: traust-java-input-validation-xxe-factory
        SAXParserFactory spf = SAXParserFactory.newInstance();
    }

    void xmlHardened() throws Exception {
        // ok: traust-java-input-validation-xxe-factory
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    }

    void staxHardened() throws Exception {
        // ok: traust-java-input-validation-xxe-factory
        XMLInputFactory xif = XMLInputFactory.newInstance();
        xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);
    }

    void formats(java.util.Formatter formatter, String userValue, StringBuilder buf) {
        // ruleid: traust-java-input-validation-variable-format-string
        String s = String.format(userValue);
        // ruleid: traust-java-input-validation-variable-format-string
        formatter.format(buf.toString());
        // ruleid: traust-java-input-validation-variable-format-string
        System.out.printf(userValue);

        // ok: traust-java-input-validation-variable-format-string
        String ok1 = String.format("%s", userValue);
        // ok: traust-java-input-validation-variable-format-string
        formatter.format("%s", buf.toString());
    }

    static final String JSON_PARSING_ERROR = "failed to parse: %s";

    void constantFormats() {
        // compile-time constants referenced by name are literals in practice
        // ok: traust-java-input-validation-variable-format-string
        String a = String.format(JSON_PARSING_ERROR);
        // ok: traust-java-input-validation-variable-format-string
        String b = String.format(AnalyzerErrorConstants.AutotuneObjectErrors.UNSUPPORTED);
        // ok: traust-java-input-validation-variable-format-string
        System.out.printf(JSON_PARSING_ERROR);
    }

    void dateFormatterNotASink(java.text.DateFormat dateFormat, java.text.NumberFormat numberFormat, long millis) {
        // ok: traust-java-input-validation-variable-format-string
        String d = dateFormat.format(new java.util.Date(millis));
        // ok: traust-java-input-validation-variable-format-string
        String n = numberFormat.format(millis);
    }
}
