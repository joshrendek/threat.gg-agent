package postgres

import (
	"context"
	"time"

	wire "github.com/jeroenrinzema/psql-wire"
	"github.com/lib/pq/oid"
)

const layout = "2006-01-02 15:04:05-07"

var responses = map[string]struct {
	Columns wire.Columns
	Rows    [][]string
}{
	"select datname from pg_database;": {
		Columns: wire.Columns{
			{
				Table: 0,
				Name:  "datname",
				Oid:   oid.T_text,
				Width: 256,
			},
		},
		Rows: [][]string{
			{"postgres"},
			{"template0"},
			{"template1"},
			{"employee_records"},
			{"financial_data"},
			{"customer_info"},
			{"sales_db"},
			{"development_db"},
			{"archive_2023"},
			{"logs"},
		},
	},
	"select * from pg_catalog.pg_user where usename='pgg_superadmins';": {
		//  usename | usesysid | usecreatedb | usesuper
		// | userepl | usebypassrls | passwd | valuntil | useconfig
		Columns: wire.Columns{
			{
				Table: 0,
				Name:  "usename",
				Oid:   oid.T_name,
				Width: 64,
			},
			{
				Table: 0,
				Name:  "usesysid",
				Oid:   oid.T_oid,
				Width: 4,
			},
			{
				Table: 0,
				Name:  "usecreatedb",
				Oid:   oid.T_bool,
				Width: 1,
			},
			{
				Table: 0,
				Name:  "usesuper",
				Oid:   oid.T_bool,
				Width: 1,
			},
			{
				Table: 0,
				Name:  "userepl",
				Oid:   oid.T_bool,
				Width: 1,
			},
			{
				Table: 0,
				Name:  "usebypassrls",
				Oid:   oid.T_bool,
				Width: 1,
			},
			{
				Table: 0,
				Name:  "passwd",
				Oid:   oid.T_text,
				Width: 64,
			},
			{
				Table: 0,
				Name:  "valuntil",
				Oid:   oid.T_timestamptz,
				Width: 8,
			},
			{
				Table: 0,
				Name:  "useconfig",
				Oid:   oid.T_text,
				Width: 64,
			},
		},
		Rows: [][]string{
			{"pgg_superadmins", "10", "f", "t", "f",
				"f", "md5c4ca4238a0b923820dcc509a6f75849b",
				time.Date(time.Now().Year(), 12, 30, 20, 0, 0, 0, time.Local).Format(layout), ""},
		},
	},
}

/*
 postgres
 template0
 template1
 employee_records
 financial_data
 customer_info
 sales_db
 development_db
 archive_2023
 logs
*/

var table = wire.Columns{
	{
		Table: 0,
		Name:  "datname",
		Oid:   oid.T_text,
		Width: 256,
	},
}

func queryResponseFor(query string) wire.PreparedStatements {

	handle := func(ctx context.Context, writer wire.DataWriter, parameters []wire.Parameter) error {
		writer.Row([]any{"postgres"})  //nolint:errcheck
		writer.Row([]any{"template0"}) //nolint:errcheck
		return writer.Complete("SELECT 2")
	}

	p := wire.Prepared(wire.NewStatement(handle, wire.WithColumns(table)))
	return p
}
