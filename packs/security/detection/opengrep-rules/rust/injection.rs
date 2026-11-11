use std::process::Command;

async fn find_orders(pool: &PgPool, region: &str) -> Result<()> {
    // ruleid: traust-rust-injection-sql-format
    let rows = sqlx::query(&format!("SELECT * FROM orders WHERE region = '{}'", region))
        .fetch_all(pool)
        .await?;
    let q = format!("DELETE FROM carts WHERE owner = '{owner}'", owner = region);
    // ruleid: traust-rust-injection-sql-format
    client.execute(&q, &[]).await?;
    // ruleid: traust-rust-injection-sql-format
    diesel::sql_query(format!("SELECT * FROM t WHERE k = {}", region)).load::<Row>(conn)?;
    // ok: traust-rust-injection-sql-format
    sqlx::query("SELECT * FROM orders WHERE region = $1").bind(region).fetch_all(pool).await?;
    // ok: traust-rust-injection-sql-format
    client.execute("DELETE FROM carts WHERE owner = $1", &[&region]).await?;
    Ok(())
}

fn convert(input: &str) {
    // ruleid: traust-rust-injection-shell-format
    Command::new("sh").arg("-c").arg(format!("convert {} out.png", input)).status().unwrap();
    let line = format!("tar -xf {}", input);
    // ruleid: traust-rust-injection-shell-format
    Command::new("bash").args(["-c", &line]).status().unwrap();
    // ok: traust-rust-injection-shell-format
    Command::new("convert").arg(input).arg("out.png").status().unwrap();
    // ok: traust-rust-injection-shell-format
    Command::new("sh").arg("-c").arg("make clean").status().unwrap();
}
