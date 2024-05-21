package errors

import (
	"net/http"

	"github.com/joomcode/errorx"
)

type ErrorType struct {
	StatusCode int
	ErrorType  *errorx.Type
}

var Error = []ErrorType{
	{
		StatusCode: http.StatusBadRequest,
		ErrorType:  ErrInvalidUserInput,
	}, {
		StatusCode: http.StatusInternalServerError,
		ErrorType:  ErrUnableTocreate,
	}, {
		StatusCode: http.StatusInternalServerError,
		ErrorType:  ErrDataAlredyExist,
	}, {
		StatusCode: http.StatusInternalServerError,
		ErrorType:  ErrUnableToGet,
	}, {
		StatusCode: http.StatusBadRequest,
		ErrorType:  ErrUnableToUpdate,
	}, {
		StatusCode: http.StatusInternalServerError,
		ErrorType:  ErrDBDelError,
	}, {
		StatusCode: http.StatusInternalServerError,
		ErrorType:  ErrUnExpectedError,
	}, {
		StatusCode: http.StatusInternalServerError,
		ErrorType:  ErrUnExternalError,
	},
}

// list of error namespaces
var (
	invalidInput    = errorx.NewNamespace("validation error").ApplyModifiers(errorx.TypeModifierOmitStackTrace)
	databaseError   = errorx.NewNamespace("database error").ApplyModifiers(errorx.TypeModifierOmitStackTrace)
	unexpectedError = errorx.NewNamespace("unexpected error").ApplyModifiers(errorx.TypeModifierOmitStackTrace)
	externalError   = errorx.NewNamespace("external error").ApplyModifiers(errorx.TypeModifierOmitStackTrace)
)

// list of errors types in all of the above namespaces

var (
	ErrInvalidUserInput = errorx.NewType(invalidInput, "invalid user input")
	ErrUnableTocreate   = errorx.NewType(databaseError, "unable to create")
	ErrDataAlredyExist  = errorx.NewType(databaseError, "data alredy exist")
	ErrUnableToGet      = errorx.NewType(databaseError, "unable to get")
	ErrUnableToUpdate   = errorx.NewType(databaseError, "unable to update")
	ErrDBDelError       = errorx.NewType(databaseError, "could not delete record")
	ErrUnExpectedError  = errorx.NewType(unexpectedError, "unexpected error")
	ErrUnExternalError  = errorx.NewType(externalError, "external error")
)
