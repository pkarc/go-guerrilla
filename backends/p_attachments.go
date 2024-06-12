package backends

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"strings"

	"github.com/phires/go-guerrilla/mail"
)

// ----------------------------------------------------------------------------------
// Processor Name: attachments
// ----------------------------------------------------------------------------------
// Description   : Parses the attachments
// ----------------------------------------------------------------------------------
// Config Options: none
// --------------:-------------------------------------------------------------------
// Input         : envelope
// ----------------------------------------------------------------------------------
// Output        : Attachments will be populated in e.Attachments
// ----------------------------------------------------------------------------------
func init() {
	processors["attachments"] = func() Decorator {
		return GetAttachment()
	}
}

const contentTypeMultipartMixed = "multipart/mixed"

func parseAttachments(e *mail.Envelope) (attachments []mail.Attachment, err error) {

	contentType := e.Header.Get("Content-Type")
	if contentType == "" {
		return nil, errors.New("no content type found")
	}

	contentType, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return nil, err
	}

	if params["boundary"] == "" {
		return nil, errors.New("no boundary found")
	}

	if contentType != contentTypeMultipartMixed {
		return attachments, errors.New("content type is not multipart/mixed")
	}

	p := multipart.NewReader(e.NewReader(), params["boundary"])
	for {
		part, err := p.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		if isAttachment(part) {
			attachment, err := decodeAttachment(part)
			if err != nil {
				return nil, err
			}
			attachments = append(attachments, attachment)
		}
	}

	return attachments, nil

}

func isAttachment(part *multipart.Part) bool {
	return part.FileName() != ""
}

func decodeAttachment(part *multipart.Part) (at mail.Attachment, err error) {
	filename := decodeMimeSentence(part.FileName())
	decoded, err := decodeContent(part, part.Header.Get("Content-Transfer-Encoding"))
	if err != nil {
		return
	}

	at.Filename = filename
	at.Data = decoded
	at.ContentType = strings.Split(part.Header.Get("Content-Type"), ";")[0]

	return
}

func decodeContent(content io.Reader, encoding string) (io.Reader, error) {
	switch strings.ToLower(encoding) {
	case "base64":
		decoded := base64.NewDecoder(base64.StdEncoding, content)
		b, err := ioutil.ReadAll(decoded)
		if err != nil {
			return nil, err
		}
		return bytes.NewReader(b), nil
	case "quoted-printable":
		decoded := quotedprintable.NewReader(content)
		b, err := ioutil.ReadAll(decoded)
		if err != nil {
			return nil, err
		}
		return bytes.NewReader(b), nil
	// The values "8bit", "7bit", and "binary" all imply that NO encoding has been performed and data need to be read as bytes.
	// "7bit" means that the data is all represented as short lines of US-ASCII data.
	// "8bit" means that the lines are short, but there may be non-ASCII characters (octets with the high-order bit set).
	// "Binary" means that not only may non-ASCII characters be present, but also that the lines are not necessarily short enough for SMTP transport.
	case "", "7bit", "8bit", "binary":
		decoded := quotedprintable.NewReader(content)
		b, err := io.ReadAll(decoded)
		if err != nil {
			return nil, err
		}
		return bytes.NewReader(b), nil
	default:
		return nil, fmt.Errorf("unknown encoding: %s", encoding)
	}
}

func decodeMimeSentence(s string) string {
	result := []string{}
	ss := strings.Split(s, " ")

	for _, word := range ss {
		dec := new(mime.WordDecoder)
		w, err := dec.Decode(word)
		if err != nil {
			if len(result) == 0 {
				w = word
			} else {
				w = " " + word
			}
		}

		result = append(result, w)
	}

	return strings.Join(result, "")
}

func GetAttachment() Decorator {
	return func(p Processor) Processor {
		return ProcessWith(func(e *mail.Envelope, task SelectTask) (Result, error) {
			if task == TaskSaveMail {

				// parse attachments
				attachments, err := parseAttachments(e)
				if err != nil {
					Log().Info(err)
				}

				if len(attachments) > 0 {
					e.Attachments = attachments
				}

				// next processor
				return p.Process(e, task)
			} else {
				// next processor
				return p.Process(e, task)
			}
		})
	}
}
