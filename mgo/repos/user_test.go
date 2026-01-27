package repos

import (
	"testing"

	"go.mongodb.org/mongo-driver/v2/bson"
)

func TestValidateUserUpdateFields(t *testing.T) {
	tests := []struct {
		name    string
		fields  bson.M
		wantErr bool
	}{
		{
			name: "valid fields",
			fields: bson.M{
				"email":       "new@example.com",
				"is_verified": true,
			},
			wantErr: false,
		},
		{
			name:    "empty fields",
			fields:  bson.M{},
			wantErr: false,
		},
		{
			name: "invalid field _id",
			fields: bson.M{
				"_id": "someid",
			},
			wantErr: true,
		},
		{
			name: "invalid field random",
			fields: bson.M{
				"random": "value",
			},
			wantErr: true,
		},
		{
			name: "mixed valid and invalid",
			fields: bson.M{
				"email":  "valid@example.com",
				"hacker": "true",
			},
			wantErr: true,
		},
		{
			name: "all valid fields",
			fields: bson.M{
				"email":         "",
				"username":      "",
				"password_hash": "",
				"role":          "",
				"is_verified":   true,
				"created_at":    nil,
				"updated_at":    nil,
				"verified_at":   nil,
				"last_login_at": nil,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateUserUpdateFields(tt.fields)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateUserUpdateFields() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
