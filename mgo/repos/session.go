package repos

import (
	"context"
	"errors"
	"time"

	"github.com/deicod/auth/internal/ctxutil"
	"github.com/deicod/auth/mgo/models"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

type SessionRepository struct {
	coll    *mongo.Collection
	timeout time.Duration
}

func NewSessionRepository(coll *mongo.Collection, timeout time.Duration) *SessionRepository {
	return &SessionRepository{coll: coll, timeout: timeout}
}

func (r *SessionRepository) withContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if r.timeout <= 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, r.timeout)
}

func (r *SessionRepository) Create(ctx context.Context, session models.Session) (models.Session, error) {
	ctx, cancel := r.withContext(ctx)
	defer cancel()

	if session.ID.IsZero() {
		session.ID = primitive.NewObjectID()
	}
	_, err := r.coll.InsertOne(ctx, session)
	return session, ctxutil.NormalizeError(err, "mgo.session.insert")
}

func (r *SessionRepository) FindByTokenHash(ctx context.Context, hash string) (models.Session, error) {
	ctx, cancel := r.withContext(ctx)
	defer cancel()

	var session models.Session
	err := r.coll.FindOne(ctx, bson.M{"token_hash": hash}).Decode(&session)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return session, err
		}
		return session, ctxutil.NormalizeError(err, "mgo.session.find_by_hash")
	}
	return session, nil
}

func (r *SessionRepository) Revoke(ctx context.Context, id primitive.ObjectID) error {
	ctx, cancel := r.withContext(ctx)
	defer cancel()

	_, err := r.coll.UpdateByID(ctx, id, bson.M{"$set": bson.M{"revoked": true}})
	return ctxutil.NormalizeError(err, "mgo.session.revoke")
}
