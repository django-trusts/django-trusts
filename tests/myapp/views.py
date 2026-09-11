from trusts.decorators import permission_required


@permission_required('myapp.change_document', fieldlookups_kwargs={'pk': 'pk'})
def edit_document(request, pk):
    return 'ok'
