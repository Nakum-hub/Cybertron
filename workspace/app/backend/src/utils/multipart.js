const { ServiceError } = require('../auth-service');

function getBusboy() {
  try {
    // eslint-disable-next-line global-require
    return require('busboy');
  } catch {
    throw new ServiceError(
      500,
      'multipart_unavailable',
      'Multipart parser is unavailable. Install busboy dependency.'
    );
  }
}

async function parseMultipartForm(request, options = {}) {
  const contentType = String(request.headers['content-type'] || '').toLowerCase();
  if (!contentType.includes('multipart/form-data')) {
    throw new ServiceError(
      415,
      'invalid_content_type',
      'Content-Type must be multipart/form-data for file upload.'
    );
  }

  const Busboy = getBusboy();
  const maxFileSize = Number(options.maxFileSize || 0);
  const limits = {
    files: 1,
    fields: Number(options.maxFields || 20),
    fieldSize: Number(options.maxFieldSize || 64 * 1024),
    fileSize: maxFileSize > 0 ? maxFileSize : undefined,
  };

  return new Promise((resolve, reject) => {
    const fields = {};
    const file = {
      buffer: null,
      fileName: '',
      mimeType: '',
      sizeBytes: 0,
    };

    let fileFound = false;
    let failed = false;

    function fail(error) {
      if (failed) {
        return;
      }
      failed = true;
      reject(error);
    }

    let busboy;
    try {
      busboy = Busboy({
        headers: request.headers,
        limits,
      });
    } catch (error) {
      fail(
        new ServiceError(
          400,
          'invalid_multipart_payload',
          error instanceof Error ? error.message : 'Invalid multipart payload.'
        )
      );
      return;
    }

    busboy.on('field', (fieldName, value) => {
      fields[fieldName] = String(value || '');
    });

    busboy.on('file', (fieldName, stream, info) => {
      if (fieldName !== 'file') {
        stream.resume();
        return;
      }

      if (fileFound) {
        stream.resume();
        return;
      }

      fileFound = true;
      file.fileName = String(info?.filename || '');
      file.mimeType = String(info?.mimeType || '');
      const chunks = [];
      let size = 0;

      stream.on('limit', () => {
        fail(
          new ServiceError(
            413,
            'upload_too_large',
            maxFileSize
              ? `Uploaded file exceeds ${maxFileSize} bytes.`
              : 'Uploaded file exceeds allowed size.'
          )
        );
      });

      stream.on('data', chunk => {
        if (failed) {
          return;
        }
        size += chunk.length;
        chunks.push(chunk);
      });

      stream.on('error', () => {
        fail(new ServiceError(400, 'invalid_upload_stream', 'Could not read uploaded file stream.'));
      });

      stream.on('end', () => {
        if (failed) {
          return;
        }
        file.buffer = chunks.length ? Buffer.concat(chunks) : Buffer.alloc(0);
        file.sizeBytes = size;
      });
    });

    busboy.on('filesLimit', () => {
      fail(new ServiceError(400, 'too_many_files', 'Only one file can be uploaded per request.'));
    });

    busboy.on('partsLimit', () => {
      fail(new ServiceError(400, 'multipart_too_many_parts', 'Multipart payload has too many parts.'));
    });

    busboy.on('fieldsLimit', () => {
      fail(new ServiceError(400, 'multipart_too_many_fields', 'Multipart payload has too many fields.'));
    });

    busboy.on('error', () => {
      fail(new ServiceError(400, 'invalid_multipart_payload', 'Failed to parse multipart form payload.'));
    });

    busboy.on('finish', () => {
      if (failed) {
        return;
      }

      if (!fileFound || !file.buffer) {
        fail(new ServiceError(400, 'file_missing', 'Field "file" is required in multipart payload.'));
        return;
      }

      resolve({ fields, file });
    });

    request.pipe(busboy);
  });
}

module.exports = {
  parseMultipartForm,
};
