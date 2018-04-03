from django.contrib import messages
from django.contrib.auth.mixins import ( 
    LoginRequiredMixin,
    PermissionRequiredMixin
)
from django.contrib.auth.models import Group, Permission
from django.contrib.auth.models import User
from django.core.urlresolvers import reverse_lazy
from django.http import Http404
from django.views import generic

from braces.views import SelectRelatedMixin

from . import forms
from . import models


class AllPosts(SelectRelatedMixin, generic.ListView):
    model = models.Post
    select_related = ("user", "community")


class UserPosts(generic.ListView):
    model = models.Post
    template_name = "posts/user_timeline.html"

    def get_queryset(self):
        try:
            self.post_user = User.objects.prefetch_related("posts").get(
                username__iexact=self.kwargs.get("username")
            )
        except User.DoesNotExist:
            raise Http404
        else:
            return self.post_user.posts.all()

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["post_user"] = self.post_user
        return context


class SinglePost(SelectRelatedMixin, generic.DetailView):
    model = models.Post
    select_related = ("user", "community")

    def get_queryset(self):
        queryset = super().get_queryset()
        return queryset.filter(
            user__username__iexact=self.kwargs.get("username")
        )


class CreatePost(LoginRequiredMixin, generic.CreateView):
    form_class = forms.PostForm
    model = models.Post

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs.update({"user": self.request.user})
        return kwargs

    def form_valid(self, form):
        self.object = form.save(commit=False)
        self.object.user = self.request.user
        self.object.save()
        return super().form_valid(form)


class DeletePost(LoginRequiredMixin, SelectRelatedMixin, generic.DeleteView):
    model = models.Post
    select_related = ("user", "community")
    success_url = reverse_lazy("posts:all")

    def get_queryset(self):
        queryset = super().get_queryset()
        return queryset.filter(user_id=self.request.user.id)

    def delete(self, *args, **kwargs):
        messages.success(self.request, "Message successfully deleted")
        return super().delete(*args, **kwargs)

class ChangeStatus(
        LoginRequiredMixin,
        PermissionRequiredMixin,
        generic.RedirectView
        ):
        permission_required = "communities.ban_member"

        def has_permission(self):
            return any([
                super().has_permission(),
                self.request.user.id in self.get_object().admins
            ])

        def get_object(self):
            return get_object_or_404(
                models.Community,
                slug=self.kwargs.get("slug")
            )

        def get_redirect_url(self, *args, **kwargs):
            return self.get_object().get_absolute_url()

        def get(self, request, *args, **kwargs):
            role = int(self.kwargs.get_status("status"))
            membership = get_object_or_404(
                models.CommunityMember,
                commuinty__slug=self.kwargs.get("slug"),
                user__id=self.kwargs.get("user_id")
            )
            membership.role = role
            membership.save()

            try:
                moderators = Group.objects.get(name__iexact="moderators")
            except Group.DoesNotExist:
                moderators = Group.objects.create(name="Moderators")
                moderators.permissions.add(
                    Permissions.objects.get(codename="ban_members")
                )

            if role in [2,3]:
                membership.user.Groups.add(moderators)
            else:
                membership.user.Groups.remove(moderators)

            messages.success(request, "@ {} is now {}".format(
                membership.user.username,
                membership.get_role_display()
                )
            )

