package control

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	pb "github.com/nekopass/nekopass/internal/protocol"
)

func validateStateRestore(r *pb.AgentMessage, credential string) error {
	if !r.RestoreState {
		return nil
	}
	if r.ProtocolVersion < 15 || credential == "" || len(r.Usage) != 0 || len(r.RuleUsage) != 0 || len(r.RequestUsers) != 0 || r.ActiveConnections != 0 || r.AppliedRevision != 0 {
		return errors.New("state restore requires an authenticated, unused Agent state")
	}
	return nil
}

// The exclusive Connect advisory lock prevents two machines using the node at
// once. A replacement never reuses old finite grants whose offline spend is lost.
func settleLostNodeState(ctx context.Context, tx pgx.Tx, node int64) error {
	_, err := tx.Exec(ctx, "UPDATE grants SET spent=issued-released WHERE node_id=$1 AND spent<issued-released", node)
	return err
}

func appendStateRestore(ctx context.Context, tx pgx.Tx, node int64, r *pb.AgentMessage, out *pb.ControlMessage) error {
	if !r.RestoreState {
		return nil
	}
	restore := &pb.StateRestore{InstanceId: r.InstanceId}
	ids, epochs := []int64{}, []int64{}
	for _, user := range out.Users {
		ids = append(ids, user.Id)
		epochs = append(epochs, user.QuotaEpoch)
	}
	rows, err := tx.Query(ctx, `SELECT user_id,quota_epoch,issued,spent,released,traffic,unlimited_spent FROM grants WHERE node_id=$1 AND (user_id,quota_epoch) IN (SELECT unnest($2::bigint[]),unnest($3::bigint[])) ORDER BY user_id`, node, ids, epochs)
	if err != nil {
		return err
	}
	for rows.Next() {
		v := &pb.UserStateBaseline{}
		if err = rows.Scan(&v.UserId, &v.QuotaEpoch, &v.Issued, &v.Spent, &v.Released, &v.Traffic, &v.UnlimitedSpent); err != nil {
			rows.Close()
			return err
		}
		restore.Users = append(restore.Users, v)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	rows, err = tx.Query(ctx, "SELECT rule_id,traffic FROM rule_usage WHERE node_id=$1 ORDER BY rule_id", node)
	if err != nil {
		return err
	}
	for rows.Next() {
		v := &pb.RuleUsage{}
		if err = rows.Scan(&v.RuleId, &v.Traffic); err != nil {
			rows.Close()
			return err
		}
		restore.Rules = append(restore.Rules, v)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	out.StateRestore = restore
	return nil
}
