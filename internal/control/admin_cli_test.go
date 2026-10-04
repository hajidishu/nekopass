package control

import (
	"context"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestLocalAdministratorResetScopeAndRevocation(t *testing.T) {
	p := testDB(t)
	ctx := context.Background()
	a, _ := testUser(t, p, 1<<20, 10, true)
	b, _ := testUser(t, p, 1<<20, 10, true)
	u, _ := testUser(t, p, 1<<20, 10, false)
	var aName, bName, uName, oldA, oldB string
	if err := p.QueryRow(ctx, "SELECT username,password_hash FROM users WHERE id=$1", a).Scan(&aName, &oldA); err != nil {
		t.Fatal(err)
	}
	if err := p.QueryRow(ctx, "SELECT username,password_hash FROM users WHERE id=$1", b).Scan(&bName, &oldB); err != nil {
		t.Fatal(err)
	}
	if err := p.QueryRow(ctx, "SELECT username FROM users WHERE id=$1", u).Scan(&uName); err != nil {
		t.Fatal(err)
	}
	for _, id := range []int64{a, b} {
		if _, err := p.Exec(ctx, "INSERT INTO sessions VALUES($1,$2,now()+interval '1 hour')", Hash(Secret()), id); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"", uName, Secret()} {
		if _, _, err := ResetAdministratorPassword(ctx, p, name); err == nil {
			t.Fatal("ambiguous/non-admin/missing account accepted")
		}
	}
	name, password, err := ResetAdministratorPassword(ctx, p, aName)
	if err != nil {
		t.Fatal(err)
	}
	if name != aName || len(password) != 32 {
		t.Fatal("invalid generated credential")
	}
	var currentA, currentB string
	var aSessions, bSessions int
	if err = p.QueryRow(ctx, "SELECT password_hash FROM users WHERE id=$1", a).Scan(&currentA); err != nil {
		t.Fatal(err)
	}
	if err = p.QueryRow(ctx, "SELECT password_hash FROM users WHERE id=$1", b).Scan(&currentB); err != nil {
		t.Fatal(err)
	}
	if currentA == oldA || currentB != oldB || bcrypt.CompareHashAndPassword([]byte(currentA), []byte(password)) != nil {
		t.Fatal("password scope/hash incorrect")
	}
	p.QueryRow(ctx, "SELECT count(*) FROM sessions WHERE user_id=$1", a).Scan(&aSessions)
	p.QueryRow(ctx, "SELECT count(*) FROM sessions WHERE user_id=$1", b).Scan(&bSessions)
	if aSessions != 0 || bSessions != 1 {
		t.Fatal("session revocation affected wrong account")
	}
	if _, err = p.Exec(ctx, "UPDATE users SET enabled=false WHERE id=$1", b); err != nil {
		t.Fatal(err)
	}
	if _, _, err = ResetAdministratorPassword(ctx, p, bName); err == nil {
		t.Fatal("disabled admin reactivated")
	}
}
