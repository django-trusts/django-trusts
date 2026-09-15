from tests.myapp.models import Document
from trusts.decorators import authorization_required


@authorization_required(Document, 'myapp.change_document')
def edit_document(request, pk):
    return 'ok'
