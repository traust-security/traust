import java.sql.Connection;
import java.sql.Statement;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import javax.persistence.EntityManager;

class InjectionTests {

    void sql(Statement stmt, Connection conn, EntityManager em, String user) throws Exception {
        // ruleid: traust-java-injection-sql-concat
        ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE name = '" + user + "'");
        // ruleid: traust-java-injection-sql-concat
        stmt.executeUpdate("DELETE FROM sessions WHERE owner = '" + user + "'");
        // ruleid: traust-java-injection-sql-concat
        stmt.execute("UPDATE t SET v = 1 WHERE k = '" + user);
        // ruleid: traust-java-injection-sql-concat
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE name = '" + user + "'");
        // ruleid: traust-java-injection-sql-concat
        em.createNativeQuery("SELECT * FROM users WHERE name = '" + user + "'");

        // ruleid: traust-java-injection-sql-concat
        stmt.execute(String.format("SELECT * FROM %s WHERE owner = '%s'", table, owner));
        // ruleid: traust-java-injection-sql-concat
        stmt.execute(format("DELETE FROM carts WHERE id = '%s'", cartId));
        String two = "select o from Order o where o.region = '" + region + "' and o.label like '%" + q + "%'";
        // ruleid: traust-java-injection-sql-concat
        em.createQuery(two, Order.class).getResultList();
        String jpql = "select o from Order o where o.region = '" + region + "'";
        // ruleid: traust-java-injection-sql-concat
        em.createQuery(jpql, Order.class).getResultList();
        // ruleid: traust-java-injection-sql-concat
        session.createSQLQuery("SELECT * FROM t WHERE k = " + key);
        // ruleid: traust-java-injection-sql-concat
        jdbc.queryForList("SELECT * FROM t WHERE owner = '" + user + "'");

        // ok: traust-java-injection-sql-concat
        em.createQuery("select o from Order o where o.region = :region", Order.class).setParameter("region", region);
        // ok: traust-java-injection-sql-concat
        stmt.executeQuery("SELECT * FROM users " + "WHERE active = 1");
        Integer orderId = order.getId();
        // ok: traust-java-injection-sql-concat
        em.createQuery("DELETE FROM Order o WHERE o.id=" + orderId).executeUpdate();
        String fixedQuery = "select o from Order o";
        // ok: traust-java-injection-sql-concat
        em.createQuery(fixedQuery, Order.class);
        // ok: traust-java-injection-sql-concat
        log.info(String.format("loaded %s", user));
        // ok: traust-java-injection-sql-concat
        PreparedStatement safe = conn.prepareStatement("SELECT * FROM users WHERE name = ?");
        safe.setString(1, user);
        // ok: traust-java-injection-sql-concat
        ResultSet fixed = stmt.executeQuery("SELECT COUNT(*) FROM users");
    }

    void exec(String host) throws Exception {
        // ruleid: traust-java-injection-exec-concat
        Runtime.getRuntime().exec("ping -c 1 " + host);
        Runtime rt = Runtime.getRuntime();
        // ruleid: traust-java-injection-exec-concat
        rt.exec("nslookup " + host + " 8.8.8.8");
        // ruleid: traust-java-injection-exec-concat
        new ProcessBuilder("sh", "-c", "dig " + host);

        // ok: traust-java-injection-exec-concat
        Runtime.getRuntime().exec(new String[]{"ping", "-c", "1", host});
        // ok: traust-java-injection-exec-concat
        new ProcessBuilder("ping", "-c", "1", host);
    }

    Object evaluate(String rule, ExpressionParser parser, ScriptEngine engine) throws Exception {
        // ruleid: traust-java-injection-expression-language
        Object a = parser.parseExpression(rule).getValue(context);
        // ruleid: traust-java-injection-expression-language
        Object b = engine.eval(rule);
        // ruleid: traust-java-injection-expression-language
        Object c = Ognl.getValue(rule, root);
        // ok: traust-java-injection-expression-language
        Object d = parser.parseExpression("price * quantity").getValue(context);
        return a;
    }
}
