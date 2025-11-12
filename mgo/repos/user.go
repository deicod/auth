package repos

import (
	"context"
	"time"

	"github.com/deicod/auth/mgo/models"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

type UserRepository struct {
	coll    *mongo.Collection
	timeout time.Duration
}

func NewUserRepository(coll *mongo.Collection, timeout time.Duration) *UserRepository {
	return &UserRepository{coll: coll, timeout: timeout}
}

func (r *UserRepository) withContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if r.timeout <= 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, r.timeout)
}

func (r *UserRepository) Create(ctx context.Context, user models.User) (models.User, error) {
	ctx, cancel := r.withContext(ctx)
	defer cancel()

	if user.ID.IsZero() {
		user.ID = primitive.NewObjectID()
	}
	_, err := r.coll.InsertOne(ctx, user)
	return user, err
}

func (r *UserRepository) FindByEmail(ctx context.Context, email string) (models.User, error) {
	ctx, cancel := r.withContext(ctx)
	defer cancel()

	var user models.User
	err := r.coll.FindOne(ctx, bson.M{"email": email}).Decode(&user)
	return user, err
}

func (r *UserRepository) FindByUsername(ctx context.Context, username string) (models.User, error) {
	ctx, cancel := r.withContext(ctx)
	defer cancel()

	var user models.User
	err := r.coll.FindOne(ctx, bson.M{"username": username}).Decode(&user)
	return user, err
}

func (r *UserRepository) FindByID(ctx context.Context, id primitive.ObjectID) (models.User, error) {
	ctx, cancel := r.withContext(ctx)
	defer cancel()

	var user models.User
	err := r.coll.FindOne(ctx, bson.M{"_id": id}).Decode(&user)
	return user, err
}

func (r *UserRepository) UpdateFields(ctx context.Context, id primitive.ObjectID, fields bson.M) error {
	ctx, cancel := r.withContext(ctx)
	defer cancel()

	update := bson.M{"$set": fields}
	_, err := r.coll.UpdateByID(ctx, id, update)
	return err
}

func (r *UserRepository) DeleteByID(ctx context.Context, id primitive.ObjectID) error {
	ctx, cancel := r.withContext(ctx)
	defer cancel()

	_, err := r.coll.DeleteOne(ctx, bson.M{"_id": id})
	return err
}
